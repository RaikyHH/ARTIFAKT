FROM python:3.12-slim as base

ENV PYTHONDONTWRITEBYTECODE=1  
ENV PYTHONUNBUFFERED=1         
ENV FLASK_ENV=production       
ENV FLASK_APP=app.py

WORKDIR /app

RUN addgroup --system --gid 1001 artifaktgroup && \
    adduser --system --uid 1001 --ingroup artifaktgroup artifaktuser

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p uploads/artifacts uploads/iocs uploads/malware && \
    chown -R artifaktuser:artifaktgroup /app/uploads

USER artifaktuser

EXPOSE 8080

CMD ["gunicorn", "--workers", "4", "--bind", "0.0.0.0:8080", "app:app"]
