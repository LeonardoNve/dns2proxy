# Update and Install Dependencies
apt update -y
apt install -y python2.7 virtualenv libpcap-dev

# Create virtualenv for script
virtualenv -p python2.7 venv
source venv/bin/activate

# Install PyPi dependencies
pip install dnspython pcapy