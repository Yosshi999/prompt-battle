FROM python:3.14.4-trixie

ENV DEBIAN_FRONTEND noninteractive

RUN groupadd -r user && useradd -r -g user user

COPY --chown=root:user ./src/ /home/user/src/
RUN pip install -r /home/user/src/requirements.txt

WORKDIR /home/user/src

# USER user

CMD ["python", "-m", "app.llm"]