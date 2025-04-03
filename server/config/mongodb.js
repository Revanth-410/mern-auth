import mongoose from "mongoose";

const connectDB = async () => {
  mongoose.connection.on("connected", () =>
    console.log("Mongose is connected")
  ); // check if connected
  await mongoose.connect(`${process.env.MONGODB_URI}/mern-auth`); // connect to database
};

export default connectDB;
