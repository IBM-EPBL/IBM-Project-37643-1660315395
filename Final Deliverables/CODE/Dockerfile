FROM ubuntu
WORKDIR /app
COPY . .
RUN apt-get update && apt-get install -y libc-dev python3-dev python3-pip libxml2;
RUN pip install -r requirements.txt
CMD [ "python3" , "app.py" ]
EXPOSE 5000