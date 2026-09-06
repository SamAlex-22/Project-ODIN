import json
import logging
from pathlib import Path
from pyspark.sql import SparkSession
from pyspark.sql.functions import col, from_json
from pyspark.sql.types import StructType, StructField, StringType, DoubleType, LongType
import sys
import os

# Fix for Java 21+ Hadoop UserGroupInformation crash
os.environ["_JAVA_OPTIONS"] = "-Djava.security.manager=allow"

# Suppress noisy spark logs
logging.getLogger("py4j").setLevel(logging.ERROR)

sys.path.append("backend")
from detectors import recon, ddos, c2

ALERTS_FILE = Path("backend/alerts.json")

def write_alert(alert):
    if alert:
        print(f"[SPARK ALERT] {alert['threat_class'].upper()} | confidence={alert['confidence']} | src={alert['src_ip']}")
        with open(ALERTS_FILE, "a") as f:
            json.dump(alert, f)
            f.write("\n")

def process_batch(df, epoch_id):
    rows = df.collect()
    for row in rows:
        if not row.data:
            continue
        line = row.data.asDict()
        
        # Pass to Phase 1 Detectors seamlessly
        alert_recon = recon.process_conn_line(line)
        alert_ddos = ddos.process_conn_line(line)
        alert_c2 = c2.process_conn_line(line)
        
        write_alert(alert_recon)
        write_alert(alert_ddos)
        write_alert(alert_c2)

if __name__ == "__main__":
    print("[Spark Processor] Initializing PySpark Structured Streaming...")
    
    # We must include the Kafka SQL package
    spark = SparkSession.builder \
        .appName("NTRO_Phase2_Spark") \
        .config("spark.jars.packages", "org.apache.spark:spark-sql-kafka-0-10_2.12:3.5.0") \
        .config("spark.sql.shuffle.partitions", "2") \
        .getOrCreate()
        
    spark.sparkContext.setLogLevel("ERROR")

    # Define schema mapping Zeek JSON loosely
    schema = StructType([
        StructField("ts", DoubleType(), True),
        StructField("id.orig_h", StringType(), True),
        StructField("id.resp_h", StringType(), True),
        StructField("id.resp_p", LongType(), True),
        StructField("proto", StringType(), True)
    ])

    print("[Spark Processor] Connecting to Kafka topic 'zeek-raw'...")
    df = spark.readStream \
        .format("kafka") \
        .option("kafka.bootstrap.servers", "localhost:9092") \
        .option("subscribe", "zeek-raw") \
        .option("startingOffsets", "latest") \
        .load()

    # Parse JSON value
    parsed_df = df.select(
        from_json(col("value").cast("string"), schema).alias("data")
    )

    print("[Spark Processor] Starting stream processing...")
    query = parsed_df.writeStream \
        .foreachBatch(process_batch) \
        .start()

    query.awaitTermination()
