FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN mkdir -p static && python -c "import urllib.request; urllib.request.urlretrieve('https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js','static/chart.umd.min.js')"
COPY . .
CMD ["python", "app.py"]
