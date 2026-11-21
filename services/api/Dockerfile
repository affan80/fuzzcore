FROM python:3.10-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --uid 10001 --create-home app
COPY fuzzcore ./fuzzcore
USER 10001
CMD ["uvicorn", "fuzzcore.api:production_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
