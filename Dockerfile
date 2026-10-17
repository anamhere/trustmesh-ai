FROM python:3.12-slim AS build
ENV VIRTUAL_ENV=/opt/venv PATH="/opt/venv/bin:$PATH" PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /build
RUN python -m venv /opt/venv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM python:3.12-slim
ENV VIRTUAL_ENV=/opt/venv PATH="/opt/venv/bin:$PATH" PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN useradd --system --uid 10001 --create-home trustmesh
COPY --from=build /opt/venv /opt/venv
COPY --chown=trustmesh:trustmesh . .
USER 10001:10001
EXPOSE 8000
CMD ["sh", "-c", "alembic upgrade head && python bootstrap_admin.py && uvicorn app:app --host 0.0.0.0 --port 8000"]
