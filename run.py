from app import create_app, bootstrap_db

app = create_app()

if __name__ == '__main__':
    bootstrap_db(app)
    app.run(host='0.0.0.0', debug=True, threaded=True, port=5050)
