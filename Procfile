# web: ./wrapper.sh
web: gunicorn nofussbm:app  --access-logfile=- --error-logfile=- -w 3 -b 0.0.0.0:$PORT
