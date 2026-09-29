FROM python:3.11-slim-bookworm

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONUNBUFFERED=1 \
    SAMIGPT_CONFIG_FILE=/var/lib/samigpt/config.json

EXPOSE 8081 8082

CMD ["python", "app.py"]
