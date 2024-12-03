/*// utils/activityLogger.js
import { MongoClient } from 'mongodb';
import dotenv from 'dotenv';

dotenv.config();

const client = new MongoClient(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });
const dbName = 'auth-app';

async function connectToDatabase() {
  if (!client.isConnected()) {
    await client.connect();
  }
  return client.db(dbName);
}


export async function logUserActivity(userId, username, activityType) {
  const activity = {
    userId,
    username,
    // activityType,
    timestamp: new Date().toLocaleString(),
  };

  try {
    const db = await connectToDatabase();
    await db.collection('Activity').insertOne(activity);
  } catch (error) {
    console.error('Error logging user activity:', error);
  }
}*/