sudo docker-compose down --remove-orphans
sudo git pull
sudo docker-compose -f docker-compose-letsencrypt.yaml up -d