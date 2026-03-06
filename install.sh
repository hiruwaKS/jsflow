cd ./esprima-csv && npm i && cd ..;
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
conda deactivate
source venv/bin/activate
python3 -m pip install -r ./requirements.txt
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
echo "pwd: $SCRIPT_DIR"
export PYTHONPATH="${PYTHONPATH}:$SCRIPT_DIR/" # source ./install.sh