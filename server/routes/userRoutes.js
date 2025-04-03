import express from "express";
import userAuth from "../middleware/userAuth.js";
import { getUserData } from "../controlers/userControler.js";

const userRouter = express.Router();

userRouter.get("/data", userAuth, getUserData);

export default userRouter;
