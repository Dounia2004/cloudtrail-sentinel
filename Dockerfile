FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# Utilisateur non root ; /app/data appartient à cet utilisateur (volume nommé du compose).
RUN useradd --create-home app && mkdir -p /app/data && chown -R app:app /app
USER app

EXPOSE 8000 8501
