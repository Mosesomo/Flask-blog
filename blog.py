#!/usr/bin/python3
from flaskblog import app, db
from flask_migrate import Migrate

migrate = Migrate(app, db)

if __name__ == "__main__":
    app.run(host='localhost', port=5001, debug=True)
