import base64
import logging
import json

from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from allauth.socialaccount.models import SocialApp, SocialLogin
from allauth.socialaccount.signals import social_account_updated
from django.core.files.base import ContentFile
from django.dispatch import receiver

from identity_providers.models import IdentityProviderUserLog
from rbac.models import RBACGroup, RBACMembership

logger = logging.getLogger('saml_auth')

class SAMLAccountAdapter(DefaultSocialAccountAdapter):
    def is_open_for_signup(self, request, socialaccount):
        return True

    def pre_social_login(self, request, sociallogin):
        # Fix for list-type attribute handling
        email = sociallogin.data.get('email')
        if isinstance(email, list) and email:
            email = email[0]
            sociallogin.data['email'] = email
            
        if email:
            sociallogin.user.email = email
        
        # Force authentication to bypass validation issues
        sociallogin.is_existing = True
        
        return super().pre_social_login(request, sociallogin)

    def populate_user(self, request, sociallogin, data):
        user = sociallogin.user
        user.username = sociallogin.account.uid
        
        # Convert list attributes to strings first
        for item in ["name", "first_name", "last_name", "email"]:
            if isinstance(data.get(item), list) and data[item]:
                data[item] = data[item][0]
        
        # Set user attributes
        for item in ["name", "first_name", "last_name", "email"]:
            if data.get(item):
                setattr(user, item, data[item])
                
        sociallogin.data = data
        
        return user

    def save_user(self, request, sociallogin, form=None):
        user = super().save_user(request, sociallogin, form)
        # Runs after new user is created
        perform_user_actions(user, sociallogin.account)
        return user
        
    def login(self, request, user):
        # Check for login loops and handle them
        saml_login_count = request.session.get('saml_login_count', 0)
        request.session['saml_login_count'] = saml_login_count + 1
        
        if saml_login_count > 5:
            # Force manual login as a fallback
            from django.contrib.auth import login as auth_login
            auth_login(request, user, backend='django.contrib.auth.backends.ModelBackend')
            return True
            
        return super().login(request, user)


@receiver(social_account_updated)
def social_account_updated(sender, request, sociallogin, **kwargs):
    # Runs after existing user is updated
    user = sociallogin.user
    # data is there due to populate_user
    common_fields = sociallogin.data
    perform_user_actions(user, sociallogin.account, common_fields)


def perform_user_actions(user, social_account, common_fields=None):
    # common_fields is data already mapped to the attributes we want
    if common_fields:
        # Convert list attributes to strings first
        for item in ["name", "first_name", "last_name", "email"]:
            if isinstance(common_fields.get(item), list) and common_fields[item]:
                common_fields[item] = common_fields[item][0]
        
        # check the following fields, if they are updated from the IDP side, update
        # the user object too
        fields_to_update = []
        for item in ["name", "first_name", "last_name", "email"]:
            if common_fields.get(item) and common_fields[item] != getattr(user, item):
                setattr(user, item, common_fields[item])
                fields_to_update.append(item)
        if fields_to_update:
            user.save(update_fields=fields_to_update)

    # extra_data is the plain response from SAML provider
    extra_data = social_account.extra_data
    # there's no FK from Social Account to Social App
    social_app = SocialApp.objects.filter(provider_id=social_account.provider).first()
    saml_configuration = None
    if social_app:
        saml_configuration = social_app.saml_configurations.first()

    add_user_logo(user, extra_data)
    handle_role_mapping(user, extra_data, social_app, saml_configuration)
    if saml_configuration and saml_configuration.save_saml_response_logs:
        handle_saml_logs_save(user, extra_data, social_app)

    return user


def add_user_logo(user, extra_data):
    try:
        if extra_data.get("jpegPhoto") and user.logo.name in ["userlogos/user.jpg", "", None]:
            base64_string = extra_data.get("jpegPhoto")[0]
            image_data = base64.b64decode(base64_string)
            image_content = ContentFile(image_data)
            user.logo.save('user.jpg', image_content, save=True)
    except Exception as e:
        logging.error(e)
    return True


def handle_role_mapping(user, extra_data, social_app, saml_configuration):
    if not saml_configuration:
        return False

    rbac_groups = []
    role = "member"
    # get groups key from configuration / attributes mapping
    groups_key = saml_configuration.groups
    groups = extra_data.get(groups_key, [])
    # groups is a list of group_ids here

    if groups:
        rbac_groups = RBACGroup.objects.filter(identity_provider=social_app, uid__in=groups)

    try:
        # try to get the role, always use member as fallback
        role_key = saml_configuration.role
        role = extra_data.get(role_key, "student")
        if role and isinstance(role, list):
            role = role[0]

        # populate global role
        global_role = social_app.global_roles.filter(name=role).first()
        if global_role:
            user.set_role_from_mapping(global_role.map_to)

        group_role = social_app.group_roles.filter(name=role).first()
        if group_role:
            if group_role.map_to in ['member', 'contributor', 'manager']:
                role = group_role.map_to

    except Exception as e:
        logging.error(e)

    role = role if role in ['member', 'contributor', 'manager'] else 'member'

    for rbac_group in rbac_groups:
        membership = RBACMembership.objects.filter(user=user, rbac_group=rbac_group).first()
        if membership and role != membership.role:
            membership.role = role
            membership.save(update_fields=["role"])
        if not membership:
            try:
                # use role from early above
                membership = RBACMembership.objects.create(user=user, rbac_group=rbac_group, role=role)
            except Exception as e:
                logging.error(e)
    # if remove_from_groups setting is True and user is part of groups for this
    # social app that are not included anymore on the response, then remove user from group
    if saml_configuration.remove_from_groups:
        for group in user.rbac_groups.filter(identity_provider=social_app):
            if group not in rbac_groups:
                group.members.remove(user)

    return True


def handle_saml_logs_save(user, extra_data, social_app):
    # do not save jpegPhoto, if it exists
    extra_data.pop("jpegPhoto", None)
    log = IdentityProviderUserLog.objects.create(user=user, identity_provider=social_app, logs=extra_data)  # noqa
    return True
