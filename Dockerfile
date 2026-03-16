# PacketLens DPI - Python
FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application and tests
COPY dpi_types.py .
COPY pcap_reader.py .
COPY packet_parser.py .
COPY sni_extractor.py .
COPY rule_manager.py .
COPY dpi_engine.py .
COPY main.py .
COPY tests/ tests/
COPY pyproject.toml .

ENV PYTHONPATH=/app

# Run tests by default
CMD ["pytest", "tests/", "-v"]

# To run the DPI engine instead:
# docker run --rm -v $(pwd):/data packetlens python main.py /data/input.pcap /data/output.pcap
