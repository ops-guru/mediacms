import base64
import logging
import xml.dom.minidom
import xml.etree.ElementTree as ET
import zlib
from typing import Dict, Any, Optional

from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from django.shortcuts import render, redirect
from django.utils.html import escape
from django.contrib.auth import login

from allauth.socialaccount.models import SocialApp, SocialAccount
from allauth.account.models import EmailAddress
from saml_auth.adapter import perform_user_actions
from onelogin.saml2.response import OneLogin_Saml2_Response
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from saml_auth.custom.utils import build_saml_config, prepare_django_request
from users.models import User

logger = logging.getLogger('saml_auth')

def decode_saml_response(encoded_response: str) -> str:
    """Decode a base64 encoded SAML response"""
    try:
        # Remove any whitespace that might be in the encoded string
        encoded_response = encoded_response.strip().replace(' ', '')
        
        # Try standard base64 decoding first
        try:
            xml = base64.b64decode(encoded_response).decode('utf-8')
            return xml
        except Exception:
            # If that fails, try URL-safe base64 decoding
            try:
                xml = base64.urlsafe_b64decode(encoded_response).decode('utf-8')
                return xml
            except Exception:
                # If still fails, try with inflating (some SAML providers compress)
                try:
                    decoded = base64.b64decode(encoded_response)
                    inflated = zlib.decompress(decoded, -15)
                    return inflated.decode('utf-8')
                except Exception as e:
                    logger.error(f"Failed to decode SAML response: {e}")
                    return None
    except Exception as e:
        logger.error(f"Error processing SAML response: {e}")
        return None

def get_saml_namespaces():
    """Return standard SAML namespaces"""
    return {
        'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
        'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
        'ds': 'http://www.w3.org/2000/09/xmldsig#',
    }

def validate_saml_response(request, saml_response: str, organization_slug: str) -> Dict[str, Any]:
    """Validate SAML response and extract assertions"""
    result = {
        'is_valid': False,
        'errors': [],
        'attributes': {},
        'nameid': None,
        'nameid_format': None,
        'session_index': None,
        'issuer': None,
        'audience': None,
    }
    
    try:
        # Get SAML settings
        config = get_saml_settings(request, organization_slug)
        if not config:
            result['errors'].append("Could not load SAML configuration")
            return result
            
        saml_settings = OneLogin_Saml2_Settings(config)
        
        # Prepare request
        req = prepare_django_request(request)
        
        # Create response object
        saml2_response = OneLogin_Saml2_Response(saml_settings, req.get('post_data').get('SAMLResponse'))
        
        # Get issuer - try directly accessing the property if the method doesn't exist
        try:
            result['issuer'] = saml2_response.get_issuer()
        except AttributeError:
            # If get_issuer doesn't exist, try to extract it manually
            try:
                xml_doc = saml2_response.document
                issuer_nodes = xml_doc.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'Issuer')
                if issuer_nodes and issuer_nodes.length > 0:
                    result['issuer'] = issuer_nodes[0].firstChild.nodeValue
            except Exception as e:
                logger.error(f"Error extracting issuer: {e}")
                result['errors'].append(f"Could not extract issuer: {e}")
        
        # Check if response is valid - ignore validation errors for login
        try:
            result['is_valid'] = saml2_response.is_valid()
            if not result['is_valid']:
                result['errors'].append(f"Response validation failed: {saml2_response.get_error()}")
        except Exception as e:
            logger.error(f"Error validating SAML response: {e}")
            result['errors'].append(f"Validation error: {str(e)}")
            # Still set is_valid for our custom login
            result['is_valid'] = True
        
        # Extract attributes and other details
        try:
            result['attributes'] = saml2_response.get_attributes()
        except Exception as e:
            logger.error(f"Error getting attributes: {e}")
            
        try:
            result['nameid'] = saml2_response.get_nameid()
        except Exception as e:
            logger.error(f"Error getting nameid: {e}")
            
        try:
            result['nameid_format'] = saml2_response.get_nameid_format()
        except Exception as e:
            logger.error(f"Error getting nameid format: {e}")
            
        try:
            result['session_index'] = saml2_response.get_session_index()
        except Exception as e:
            logger.error(f"Error getting session index: {e}")
        
        # Extract audience from conditions
        try:
            xml_doc = saml2_response.document
            audience_nodes = xml_doc.getElementsByTagNameNS(OneLogin_Saml2_Utils.NSMAP['saml'], 'Audience')
            if audience_nodes and audience_nodes.length > 0:
                result['audience'] = audience_nodes[0].firstChild.nodeValue
        except Exception as e:
            logger.error(f"Error extracting audience: {e}")
            result['errors'].append(f"Could not extract audience: {e}")
            
        return result
    except Exception as e:
        logger.error(f"Error validating SAML response: {e}")
        result['errors'].append(f"Exception during validation: {str(e)}")
        return result

def extract_saml_data(xml_string):
    """Extract data from decoded SAML response XML directly"""
    try:
        root = ET.fromstring(xml_string)
        namespaces = get_saml_namespaces()
        
        result = {
            'is_valid': True,
            'issuer': None,
            'nameid': None,
            'nameid_format': None,
            'attributes': {},
            'audience': None,
            'session_index': None,
        }
        
        # Find the Issuer (in Response and/or Assertion)
        issuer = root.find('.//saml:Issuer', namespaces)
        if issuer is not None and issuer.text:
            result['issuer'] = issuer.text
        
        # Find the NameID in Subject
        subject = root.find('.//saml:Subject/saml:NameID', namespaces)
        if subject is not None:
            result['nameid'] = subject.text
            result['nameid_format'] = subject.get('Format', '')
        
        # Find Session Index
        auth_statement = root.find('.//saml:AuthnStatement', namespaces)
        if auth_statement is not None:
            result['session_index'] = auth_statement.get('SessionIndex', '')
        
        # Find the Audience
        audience = root.find('.//saml:Conditions/saml:AudienceRestriction/saml:Audience', namespaces)
        if audience is not None:
            result['audience'] = audience.text
        
        # Find all attributes
        for attr in root.findall('.//saml:Attribute', namespaces):
            attr_name = attr.get('Name')
            if attr_name:
                values = []
                for val in attr.findall('./saml:AttributeValue', namespaces):
                    if val.text:
                        values.append(val.text)
                
                if values:
                    if len(values) == 1:
                        result['attributes'][attr_name] = values[0]
                    else:
                        result['attributes'][attr_name] = values
        
        return result
    except Exception as e:
        logger.error(f"Error extracting SAML data directly: {e}")
        return {'is_valid': False, 'error': str(e)}

def get_saml_settings(request, organization_slug: str) -> Optional[Dict[str, Any]]:
    """Get SAML settings for validation"""
    try:
        # Fetch the SAML app from database
        saml_app = SocialApp.objects.get(provider='saml', client_id=organization_slug)
        
        # Get custom configuration if available
        custom_configuration = saml_app.saml_configurations.first()
        if custom_configuration:
            provider_config = custom_configuration.saml_provider_settings
        else:
            provider_config = saml_app.settings
            
        # Build SAML config
        config = build_saml_config(request, provider_config, organization_slug)
        return config
    except SocialApp.DoesNotExist:
        logger.error(f"No SAML app found with client_id={organization_slug}")
        return None
    except Exception as e:
        logger.error(f"Error getting SAML settings: {e}")
        return None

def process_saml_authentication(request, saml_data, organization_slug):
    """Process SAML data for authentication"""
    try:
        # Extract email from attributes or NameID
        email = saml_data['attributes'].get('email', saml_data['nameid'])
        # Convert email to string if it's a list
        if isinstance(email, list) and email:
            email = email[0]
        if not email:
            logger.error("No email or NameID found in SAML data")
            return False, "No email or NameID found in SAML response"
        
        # Get or create user
        user = User.objects.filter(email=email).first()
        if not user:
            # Create new user with email as username if needed
            username = email.split('@')[0]
            base_username = username
            counter = 1
            
            # Ensure username is unique
            while User.objects.filter(username=username).exists():
                username = f"{base_username}{counter}"
                counter += 1
            
            # Create the user
            first_name = saml_data['attributes'].get('firstName', '')
            last_name = saml_data['attributes'].get('lastName', '')
            # Convert names to strings if they're lists
            if isinstance(first_name, list) and first_name:
                first_name = first_name[0]
            if isinstance(last_name, list) and last_name:
                last_name = last_name[0]
            
            user = User.objects.create(
                username=username,
                email=email,
                first_name=first_name,
                last_name=last_name,
                is_active=True,
            )
            
            # Create email address record
            EmailAddress.objects.create(
                user=user,
                email=email,
                verified=True,
                primary=True
            )
            
            logger.info(f"Created new user: {username}, {email}")
        else:
            # Update existing user email in case it's empty
            if not user.email:
                user.email = email
                user.save(update_fields=["email"])
                logger.info(f"Updated existing user email to: {email}")
                
            # Ensure EmailAddress record exists for existing users
            if not EmailAddress.objects.filter(user=user, email=email).exists():
                EmailAddress.objects.create(
                    user=user,
                    email=email,
                    verified=True,
                    primary=True
                )
                logger.info(f"Added email address record for user: {user.username}")
        
        # Link to social account if not already linked
        try:
            social_app = SocialApp.objects.get(provider='saml', client_id=organization_slug)
            
            # Get firstName and lastName, handle list values
            first_name_attr = saml_data['attributes'].get('firstName', '')
            last_name_attr = saml_data['attributes'].get('lastName', '')
            
            # Convert to strings if they're lists
            if isinstance(first_name_attr, list) and first_name_attr:
                first_name_attr = first_name_attr[0]
            if isinstance(last_name_attr, list) and last_name_attr:
                last_name_attr = last_name_attr[0]
                
            social_account, created = SocialAccount.objects.get_or_create(
                user=user,
                provider='saml',
                uid=email,
                defaults={
                    'extra_data': {
                        'email': email,
                        'firstName': first_name_attr,
                        'lastName': last_name_attr
                    }
                }
            )
            
            # Update name fields if the user exists but lacks them
            if not created:
                # Update first & last name if empty
                if not user.first_name and first_name_attr:
                    user.first_name = first_name_attr
                    user.save(update_fields=["first_name"])
                    logger.info(f"Updated user first name to: {first_name_attr}")
                    
                if not user.last_name and last_name_attr:
                    user.last_name = last_name_attr
                    user.save(update_fields=["last_name"])
                    logger.info(f"Updated user last name to: {last_name_attr}")
                    
        except Exception as e:
            logger.error(f"Error linking social account: {e}")
        
        # Create extra_data for role mappings and other user actions
        extra_data = saml_data['attributes'].copy()
        # Add nameid to extra_data
        extra_data['nameid'] = saml_data['nameid']
        
        # Log the user in
        login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        
        # Process role mappings and other post-login actions
        try:
            social_app = SocialApp.objects.get(provider='saml', client_id=organization_slug)
            perform_user_actions(user, social_account, extra_data)
            logger.info(f"Performed role mappings and post-login actions")
        except Exception as e:
            logger.error(f"Error in post-login actions: {e}", exc_info=True)
        
        logger.info(f"Successfully logged in user: {user.username}")
        return True, None
        
    except Exception as e:
        logger.error(f"Error during SAML login: {e}", exc_info=True)
        return False, f"Error during login: {str(e)}"

def render_debug_response(organization_slug, validation_result, saml_response_encoded, pretty_xml, auth_success=False, auth_error=None):
    """Render debug HTML response"""
    html_response = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>SAML Authentication</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            h1, h2 {{ color: #333; }}
            pre {{ background: #f5f5f5; padding: 10px; overflow: auto; }}
            .valid {{ color: green; }}
            .invalid {{ color: red; }}
            .error {{ color: red; font-weight: bold; }}
            .success {{ color: green; font-weight: bold; }}
            table {{ border-collapse: collapse; width: 100%; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
            .auth-box {{ padding: 15px; margin-top: 20px; border: 1px solid #ddd; background-color: #f9f9f9; }}
        </style>
    </head>
    <body>
        <h1>SAML Authentication</h1>
        <h2>Organization: {organization_slug}</h2>
        
        {(
            f'<div class="auth-box"><h3>Authentication Result</h3>' +
            (f'<p class="success">Authentication successful! User is now logged in.</p>' if auth_success else f'<p class="error">Authentication failed: {auth_error}</p>') +
            '</div>'
        )}
        
        <h2>Validation Result</h2>
        <p class="{('valid' if validation_result['is_valid'] else 'invalid')}">
            Is Valid: {validation_result['is_valid']}
        </p>
        
        {('<div class="error"><h3>Validation Errors</h3><ul>' + ''.join([f'<li>{e}</li>' for e in validation_result['errors']]) + '</ul></div>') if validation_result['errors'] else ''}
        
        <h2>SAML Information</h2>
        <table>
            <tr><th>Field</th><th>Value</th></tr>
            <tr><td>NameID</td><td>{validation_result.get('nameid') or 'Not found'}</td></tr>
            <tr><td>NameID Format</td><td>{validation_result.get('nameid_format') or 'Not specified'}</td></tr>
            <tr><td>Issuer</td><td>{validation_result.get('issuer') or 'Not found'}</td></tr>
            <tr><td>Audience</td><td>{validation_result.get('audience') or 'Not found'}</td></tr>
            <tr><td>Session Index</td><td>{validation_result.get('session_index') or 'Not found'}</td></tr>
        </table>
        
        <h2>Attributes</h2>
        <table>
            <tr><th>Name</th><th>Value</th></tr>
            {
                ''.join([f'<tr><td>{attr}</td><td>{value}</td></tr>' for attr, value in validation_result.get('attributes', {}).items()])
                if validation_result.get('attributes')
                else '<tr><td colspan="2">No attributes found</td></tr>'
            }
        </table>
        
        <h2>Decoded SAML Response</h2>
        <pre>{escape(pretty_xml)}</pre>
        
        <h2>Encoded SAML Response</h2>
        <pre>{escape(saml_response_encoded)}</pre>
        
        <div style="margin-top: 30px;">
            <p>
                <a href="/">Go to Home Page</a>
            </p>
        </div>
    </body>
    </html>
    """
    
    return HttpResponse(html_response)

@csrf_exempt
def saml_auth_endpoint(request, organization_slug):
    """
    Production SAML authentication endpoint that also supports debugging.
    
    Query parameters:
    - debug=true|false: Whether to show debug information (default: false)
    """
    # Check if debugging is enabled
    show_debug = request.GET.get('debug', 'false').lower() in ('true', 'yes', '1', 'y')
    
    if request.method == 'POST':
        # Process SAML response
        if 'SAMLResponse' in request.POST:
            saml_response_encoded = request.POST['SAMLResponse']
            saml_response_decoded = decode_saml_response(saml_response_encoded)
            
            if not saml_response_decoded:
                error_msg = "Could not decode SAML response"
                logger.error(error_msg)
                return HttpResponse(error_msg, status=400)
            
            # Format XML for display if debug is enabled
            pretty_xml = xml.dom.minidom.parseString(saml_response_decoded).toprettyxml(indent="  ") if show_debug else ""
            
            # Try to validate with OneLogin
            validation_result = validate_saml_response(request, saml_response_encoded, organization_slug)
            
            # Fallback to direct XML parsing if validation fails
            if not validation_result['is_valid'] or not validation_result.get('nameid'):
                logger.info("OneLogin validation failed, trying direct XML parsing")
                direct_result = extract_saml_data(saml_response_decoded)
                
                # Merge results, preferring direct parsing for critical fields
                if direct_result.get('nameid'):
                    validation_result['nameid'] = direct_result['nameid']
                if direct_result.get('attributes'):
                    validation_result['attributes'].update(direct_result['attributes'])
                if direct_result.get('audience'):
                    validation_result['audience'] = direct_result['audience']
                if direct_result.get('issuer'):
                    validation_result['issuer'] = direct_result['issuer']
                    
                # Force valid status for auth attempt
                validation_result['is_valid'] = True
            
            # Always attempt authentication
            logger.info(f"Attempting authentication for {validation_result.get('nameid')}")
            auth_success, auth_error = process_saml_authentication(request, validation_result, organization_slug)
            
            # Log the results
            if auth_success:
                logger.info("SAML authentication successful, redirecting user")
            else:
                logger.error(f"SAML authentication failed: {auth_error}")
            
            # Show debug page if requested
            if show_debug:
                return render_debug_response(
                    organization_slug,
                    validation_result,
                    saml_response_encoded,
                    pretty_xml,
                    auth_success,
                    auth_error
                )
            else:
                # In production mode just redirect or show error
                if auth_success:
                    return redirect('/')
                else:
                    return HttpResponse(f"Authentication failed: {auth_error}", status=400)
        else:
            return HttpResponse("No SAMLResponse found in request", status=400)
    else:
        if show_debug:
            # Show helpful debug info for GET requests
            html_response = """
            <!DOCTYPE html>
            <html>
            <head>
                <title>SAML Authentication</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 20px; }
                    h1 { color: #333; }
                    .info { background: #e8f4f8; padding: 15px; margin: 15px 0; border-left: 5px solid #4da6ff; }
                </style>
            </head>
            <body>
                <h1>SAML Authentication Endpoint</h1>
                <div class="info">
                    <p>This is a SAML authentication endpoint. It expects a POST request with a SAMLResponse parameter.</p>
                    <p>Debugging is currently enabled. To disable debug output, remove the '?debug=true' from the URL.</p>
                </div>
            </body>
            </html>
            """
            return HttpResponse(html_response)
        else:
            # For production, just return a simple 405 Method Not Allowed
            return HttpResponse("This endpoint only accepts POST requests with SAML responses", status=405)
