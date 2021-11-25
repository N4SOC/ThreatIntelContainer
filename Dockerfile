FROM python:3.8-bullseye
WORKDIR /TwitterIOC
ADD . /TwitterIOC
RUN pip install -r requirements.txt
RUN chmod +x shell.sh
CMD ["sh","shell.sh"]