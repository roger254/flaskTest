import os

from flask import Flask


def create_app(test_config=None):
    # create and cofigure the app
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY='dev',
        DATABASE=os.path.join(app.instance_path, 'flaskr.sqlite')
    )

    if test_config is None:
        # load the instance config, if it exist, when not testing
        app.config.from_pyfile('config.py', silent=True)
    else:
        # load the test config if passed
        app.config.from_mapping(test_config)

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError as e:
        print(e)

    # import database and initialize
    from . import db
    db.init_app(app)

    # import and register the authentication Blueprint
    from . import auth
    app.register_blueprint(auth.bp)

    # import and register the blog Blueprint
    from . import blog
    app.register_blueprint(blog.bp)
    app.add_url_rule('/', endpoint='index')

    return app
