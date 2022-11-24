FROM python
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
CMD ["python", "app.py", "-h", "0.0.0.0"]
EXPOSE 3000
