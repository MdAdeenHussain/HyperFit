Run migrations in backend directory:

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

flask --app app db init
flask --app app db migrate -m "initial"
flask --app app db upgrade
