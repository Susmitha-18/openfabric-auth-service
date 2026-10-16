
import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import authorizationRoutes from "./routes/authorization.routes.js";

const app = express();

app.use(helmet());
app.use(cors());
app.use(express.json());

// Limit repeated requests to protect the API.
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 100,
    standardHeaders: "draft-7",
    legacyHeaders: false,
  })
);

// Health-check endpoint.
app.get("/api/health", (_req, res) => {
  res.status(200).json({
    status: "OK",
    message: "OpenFabric Authorization Service is running",
  });
});

// Authorization endpoint.
app.use("/authorize", authorizationRoutes);

export default app;
