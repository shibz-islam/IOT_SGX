kafkaProd:
  - gets data from iot devices through api calls
  - encrypts data
  - publishes messages to kafka 
kafkaConsumer:
  - collects data from kafka server
  - sends to sgx
flaskApp: generates dummy data

# To Run:
Start the Zookeeper and Kafka Server
Start the MongoDB

Then to run the kafka Consumer, submit the following in the command prompt
spark-submit --packages org.apache.spark:spark-streaming-kafka-0-8_2.11:2.4.3,org.mongodb.spark:mongo-spark-connector_2.11:2.2.0 kafkaConsumer.py localhost:2181 IOT
  
Start the kafkaProd script file
  
