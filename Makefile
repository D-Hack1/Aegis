.PHONY: up down restart status attacker victim benign zeek health iodined

up:
	docker compose up -d --build

down:
	docker compose down -v

restart:
	docker compose down -v && docker compose up -d --build

status:
	docker compose ps

attacker:
	docker exec -it attacker bash

victim:
	docker exec -it victim bash

benign:
	docker exec -it benign bash

zeek:
	docker exec -it zeek bash

iodined:
	docker exec -it attacker iodined -f -P test 192.168.99.1 tunnel.lab

health:
	docker exec kafka kafka-topics --bootstrap-server localhost:9092 --list
	python3 kafka/health_check.py
	python3 es/health_check.py
