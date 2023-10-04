FROM python:3.10-alpine

WORKDIR /usr/src/app

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# RUN apk update \
#     && apk add postgresql-dev gcc python3-dev musl-dev

# RUN addgroup -S app && adduser -S app -G app
# RUN chown -R app:app /usr/src/app/
# USER app

RUN mkdir /usr/src/app/static
RUN pip install --upgrade pip

COPY requirements.txt .

RUN pip install -r requirements.txt

COPY ./entrypoint.sh .

COPY . .

ENTRYPOINT ["./entrypoint.sh"]

