FROM python:3.7

ENV FLASK_APP run.py

COPY run.py gunicorn-cfg.py requirements.txt config.py .env ./
COPY app app

RUN pip3 install -r requirements.txt

EXPOSE 5005
CMD ["gunicorn", "--config", "gunicorn-cfg.py", "run:app"]
