FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DATA_DIR=/data
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
 && useradd --system --no-create-home app \
 && mkdir /data && chown app:app /data
COPY app ./app
USER app
EXPOSE 5000
HEALTHCHECK --interval=15s --timeout=3s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:5000/health')"
CMD ["gunicorn","-b","0.0.0.0:5000","--workers","1","--threads","4","app:create_app()"]
