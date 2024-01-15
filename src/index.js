import dotenv from "dotenv";
import app from "./app.js";
import connectDB from "./db/index.js";

dotenv.config();

connectDB()
    .then(() => {
        app.on("error", (error) => {
            console.log("Error: ", error);
            throw error;
        });

        app.listen(process.env.PORT || 8000, () => {
            console.log(` Server listening on PORT:  ${process.env.PORT}`);
        });
    })
    .catch((error) => {
        console.log("MongoDB Connection Failed !!! ", error);
    });
