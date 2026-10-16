
import { Router } from "express";
import { authorizeRequest } from "../controllers/authorization.controller.js";

const router = Router();

router.post("/", authorizeRequest);

export default router;
