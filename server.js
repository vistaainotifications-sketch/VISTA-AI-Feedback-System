import express from "express";
import helmet from "helmet";
import pg from "pg";
import bcrypt from "bcryptjs";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

const app = express();
const { Pool } = pg;

const dir = path.dirname(fileURLToPath(import.meta.url));

const PORT = process.env.PORT || 3000;

// DATABASE CONNECTION
const pool = process.env.DATABASE_URL
    ? new Pool({
        connectionString: process.env.DATABASE_URL,
        ssl: process.env.DATABASE_SSL === "false"
            ? false
            : { rejectUnauthorized: false }
    })
    : null;

// MIDDLEWARE
app.use(helmet({ contentSecurityPolicy: false }));

// CORS CONFIGURATION
const allowedOrigins = new Set([
    "https://vista-ai-frontend.onrender.com",
    "http://localhost:5173",
    "http://localhost:5175",
    process.env.FRONTEND_URL
].filter(Boolean));

app.use((req, res, next) => {
    const origin = req.headers.origin;

    if (origin && allowedOrigins.has(origin)) {
        res.setHeader("Access-Control-Allow-Origin", origin);
        res.setHeader("Vary", "Origin");
        res.setHeader(
            "Access-Control-Allow-Methods",
            "GET, POST, PATCH, DELETE, OPTIONS"
        );
        res.setHeader(
            "Access-Control-Allow-Headers",
            "Content-Type, Authorization"
        );
    }

    if (req.method === "OPTIONS") {
        return res.sendStatus(204);
    }

    next();
});

app.use(express.json({ limit: "30kb" }));
app.use(express.static(path.join(dir, "public")));

// ADMIN TOKEN STORAGE
const tokens = new Set();

// ADMIN AUTHENTICATION MIDDLEWARE
const admin = (req, res, next) => {
    const authHeader = req.headers.authorization || "";
    const match = authHeader.match(/^Bearer\s+(.+)$/i);

    if (!match) {
        return res.status(401).json({
            error: "Admin login required"
        });
    }

    const token = match[1].trim();

    if (!tokens.has(token)) {
        return res.status(401).json({
            error: "Admin login required"
        });
    }

    next();
};

// DATABASE INITIALIZATION
async function init() {
    if (!pool) {
        console.warn("DATABASE_URL is not configured.");
        return;
    }

    await pool.query(`
        CREATE TABLE IF NOT EXISTS vista_feedback (
            id BIGSERIAL PRIMARY KEY,
            full_name VARCHAR(120),
            email VARCHAR(254),
            phone VARCHAR(30),
            relationship VARCHAR(40) NOT NULL,
            overall_rating SMALLINT NOT NULL CHECK (overall_rating BETWEEN 1 AND 5),
            service_rating SMALLINT NOT NULL CHECK (service_rating BETWEEN 1 AND 5),
            website_rating SMALLINT NOT NULL CHECK (website_rating BETWEEN 1 AND 5),
            innovation_rating SMALLINT NOT NULL CHECK (innovation_rating BETWEEN 1 AND 5),
            professionalism_rating SMALLINT NOT NULL CHECK (professionalism_rating BETWEEN 1 AND 5),
            support_rating SMALLINT NOT NULL CHECK (support_rating BETWEEN 1 AND 5),
            liked TEXT,
            improvements TEXT,
            comments TEXT,
            recommend BOOLEAN NOT NULL,
            publish_consent BOOLEAN NOT NULL DEFAULT FALSE,
            status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    console.log("VISTA AI feedback database initialized.");
}

// HEALTH CHECK
app.get("/api/health", (req, res) => {
    res.json({
        ok: true,
        database: !!pool
    });
});

// PUBLIC FEEDBACK SUBMISSION
app.post("/api/feedback", async (req, res) => {
    try {
        if (!pool) {
            return res.status(503).json({
                error: "Database is not configured."
            });
        }

        const b = req.body || {};

        const ratingFields = [
            "overall_rating",
            "service_rating",
            "website_rating",
            "innovation_rating",
            "professionalism_rating",
            "support_rating"
        ];

        const relationships = [
            "Customer / Client",
            "Employee",
            "Developer",
            "Business Partner",
            "Student",
            "General Public"
        ];

        if (
            !relationships.includes(b.relationship) ||
            ratingFields.some(
                key =>
                    !Number.isInteger(Number(b[key])) ||
                    Number(b[key]) < 1 ||
                    Number(b[key]) > 5
            ) ||
            typeof b.recommend !== "boolean"
        ) {
            return res.status(400).json({
                error: "Please complete all required fields and ratings."
            });
        }

        const email = String(b.email || "")
            .trim()
            .toLowerCase();

        if (
            email &&
            !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
        ) {
            return res.status(400).json({
                error: "Enter a valid email."
            });
        }

        const result = await pool.query(
            `
            INSERT INTO vista_feedback (
                full_name,
                email,
                phone,
                relationship,
                overall_rating,
                service_rating,
                website_rating,
                innovation_rating,
                professionalism_rating,
                support_rating,
                liked,
                improvements,
                comments,
                recommend,
                publish_consent
            )
            VALUES (
                $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,
                $11,$12,$13,$14,$15
            )
            RETURNING id
            `,
            [
                String(b.full_name || "").slice(0, 120) || null,
                email || null,
                String(b.phone || "").slice(0, 30) || null,
                b.relationship,
                ...ratingFields.map(key => Number(b[key])),
                String(b.liked || "").slice(0, 3000),
                String(b.improvements || "").slice(0, 3000),
                String(b.comments || "").slice(0, 5000),
                b.recommend,
                b.publish_consent === true
            ]
        );

        return res.status(201).json({
            ok: true,
            id: result.rows[0].id,
            message: "Thank you! Your feedback has been submitted."
        });

    } catch (error) {
        console.error("Feedback submission error:", error);

        return res.status(500).json({
            error: "Unable to submit feedback."
        });
    }
});

// ADMIN LOGIN
app.post("/api/admin/login", async (req, res) => {
    try {
        if (
            !process.env.ADMIN_EMAIL ||
            !process.env.ADMIN_PASSWORD_HASH
        ) {
            return res.status(503).json({
                error: "Admin credentials not configured."
            });
        }

        const email = String(req.body?.email || "")
            .trim()
            .toLowerCase();

        const configuredEmail = process.env.ADMIN_EMAIL
            .trim()
            .toLowerCase();

        const password = String(req.body?.password || "");

        if (
            email !== configuredEmail ||
            !(await bcrypt.compare(
                password,
                process.env.ADMIN_PASSWORD_HASH
            ))
        ) {
            return res.status(401).json({
                error: "Invalid credentials"
            });
        }

        const token = crypto.randomBytes(32).toString("hex");

        tokens.add(token);

        return res.json({
            ok: true,
            token: token
        });

    } catch (error) {
        console.error("Admin login error:", error);

        return res.status(500).json({
            error: "Unable to complete admin login."
        });
    }
});

// GET ALL FEEDBACK
app.get("/api/admin/feedback", admin, async (req, res) => {
    try {
        if (!pool) {
            return res.status(503).json({
                error: "Database is not configured."
            });
        }

        const status = [
            "PENDING",
            "APPROVED",
            "REJECTED"
        ].includes(req.query.status)
            ? req.query.status
            : null;

        const result = status
            ? await pool.query(
                `
                SELECT *
                FROM vista_feedback
                WHERE status = $1
                ORDER BY created_at DESC
                `,
                [status]
            )
            : await pool.query(`
                SELECT *
                FROM vista_feedback
                ORDER BY created_at DESC
            `);

        return res.json({
            items: result.rows
        });

    } catch (error) {
        console.error("Admin feedback error:", error);

        return res.status(500).json({
            error: "Unable to load feedback."
        });
    }
});

// APPROVE / REJECT FEEDBACK
app.patch("/api/admin/feedback/:id", admin, async (req, res) => {
    try {
        const status = req.body?.status;

        if (!["PENDING", "APPROVED", "REJECTED"].includes(status)) {
            return res.status(400).json({
                error: "Invalid status"
            });
        }

        const result = await pool.query(
            `
            UPDATE vista_feedback
            SET status = $1
            WHERE id = $2
            RETURNING id, status
            `,
            [status, req.params.id]
        );

        if (!result.rowCount) {
            return res.status(404).json({
                error: "Feedback not found."
            });
        }

        return res.json({
            item: result.rows[0]
        });

    } catch (error) {
        console.error("Feedback update error:", error);

        return res.status(500).json({
            error: "Unable to update feedback."
        });
    }
});

// DELETE FEEDBACK
app.delete("/api/admin/feedback/:id", admin, async (req, res) => {
    try {
        const result = await pool.query(
            `
            DELETE FROM vista_feedback
            WHERE id = $1
            `,
            [req.params.id]
        );

        if (!result.rowCount) {
            return res.status(404).json({
                error: "Feedback not found."
            });
        }

        return res.json({
            ok: true,
            message: "Feedback deleted successfully."
        });

    } catch (error) {
        console.error("Feedback deletion error:", error);

        return res.status(500).json({
            error: "Feedback deletion failed."
        });
    }
});

// PUBLIC AGGREGATED INSIGHTS
app.get("/api/public/insights", async (req, res) => {
    try {
        if (!pool) {
            return res.status(503).json({
                error: "Database is not configured."
            });
        }

        const result = await pool.query(`
            WITH public_feedback AS (
                SELECT
                    overall_rating,
                    service_rating,
                    website_rating,
                    innovation_rating,
                    professionalism_rating,
                    support_rating,
                    recommend
                FROM vista_feedback
                WHERE status = 'APPROVED'
                  AND publish_consent = TRUE
            ),
            totals AS (
                SELECT
                    COUNT(*)::int AS total_reviews,
                    COALESCE(ROUND(AVG(overall_rating)::numeric, 2), 0) AS average_rating,
                    COALESCE(ROUND(AVG(service_rating)::numeric, 2), 0) AS service_rating,
                    COALESCE(ROUND(AVG(website_rating)::numeric, 2), 0) AS website_rating,
                    COALESCE(ROUND(AVG(innovation_rating)::numeric, 2), 0) AS innovation_rating,
                    COALESCE(ROUND(AVG(professionalism_rating)::numeric, 2), 0) AS professionalism_rating,
                    COALESCE(ROUND(AVG(support_rating)::numeric, 2), 0) AS support_rating,
                    COUNT(*) FILTER (WHERE recommend = TRUE)::int AS recommend_yes,
                    COUNT(*) FILTER (WHERE recommend = FALSE)::int AS recommend_no
                FROM public_feedback
            ),
            distribution AS (
                SELECT json_object_agg(stars, rating_count ORDER BY stars) AS rating_distribution
                FROM (
                    SELECT
                        gs.stars,
                        COUNT(p.overall_rating)::int AS rating_count
                    FROM generate_series(1, 5) AS gs(stars)
                    LEFT JOIN public_feedback p
                        ON p.overall_rating = gs.stars
                    GROUP BY gs.stars
                    ORDER BY gs.stars
                ) d
            )
            SELECT
                totals.*,
                COALESCE(
                    distribution.rating_distribution,
                    '{"1":0,"2":0,"3":0,"4":0,"5":0}'::json
                ) AS rating_distribution,
                CASE
                    WHEN totals.total_reviews = 0 THEN 0
                    ELSE ROUND(
                        100.0 * totals.recommend_yes / totals.total_reviews,
                        1
                    )
                END AS recommendation_percentage
            FROM totals
            CROSS JOIN distribution
        `);

        res.setHeader("Cache-Control", "no-store");

        return res.json({
            ...result.rows[0],
            updated_at: new Date().toISOString()
        });

    } catch (error) {
        console.error("Public insights error:", error);

        return res.status(500).json({
            error: "Unable to load review insights."
        });
    }
});

// PUBLIC AGGREGATED INSIGHTS (approved reviews with publication consent only)
app.get("/api/public/insights", async (req, res) => {
    try {
        if (!pool) {
            return res.status(503).json({ error: "Database is not configured." });
        }

        const result = await pool.query(`
            WITH public_feedback AS (
                SELECT overall_rating, service_rating, website_rating,
                       innovation_rating, professionalism_rating,
                       support_rating, recommend
                FROM vista_feedback
                WHERE status = 'APPROVED'
                  AND publish_consent = TRUE
            ),
            totals AS (
                SELECT
                    COUNT(*)::int AS total_reviews,
                    COALESCE(ROUND(AVG(overall_rating)::numeric, 2), 0) AS average_rating,
                    COALESCE(ROUND(AVG(service_rating)::numeric, 2), 0) AS service_rating,
                    COALESCE(ROUND(AVG(website_rating)::numeric, 2), 0) AS website_rating,
                    COALESCE(ROUND(AVG(innovation_rating)::numeric, 2), 0) AS innovation_rating,
                    COALESCE(ROUND(AVG(professionalism_rating)::numeric, 2), 0) AS professionalism_rating,
                    COALESCE(ROUND(AVG(support_rating)::numeric, 2), 0) AS support_rating,
                    COUNT(*) FILTER (WHERE recommend = TRUE)::int AS recommend_yes,
                    COUNT(*) FILTER (WHERE recommend = FALSE)::int AS recommend_no
                FROM public_feedback
            ),
            distribution AS (
                SELECT json_object_agg(stars, rating_count ORDER BY stars) AS rating_distribution
                FROM (
                    SELECT gs.stars, COUNT(p.overall_rating)::int AS rating_count
                    FROM generate_series(1, 5) AS gs(stars)
                    LEFT JOIN public_feedback p ON p.overall_rating = gs.stars
                    GROUP BY gs.stars
                    ORDER BY gs.stars
                ) d
            )
            SELECT totals.*,
                   COALESCE(distribution.rating_distribution, '{"1":0,"2":0,"3":0,"4":0,"5":0}'::json) AS rating_distribution,
                   CASE WHEN totals.total_reviews = 0 THEN 0
                        ELSE ROUND(100.0 * totals.recommend_yes / totals.total_reviews, 1)
                   END AS recommendation_percentage
            FROM totals CROSS JOIN distribution
        `);

        res.setHeader("Cache-Control", "no-store");
        return res.json({
            ...result.rows[0],
            updated_at: new Date().toISOString()
        });
    } catch (error) {
        console.error("Public insights error:", error);
        return res.status(500).json({ error: "Unable to load review insights." });
    }
});

// PUBLIC APPROVED REVIEWS
app.get("/api/public/reviews", async (req, res) => {
    try {
        if (!pool) {
            return res.json({
                items: []
            });
        }

        const result = await pool.query(`
            SELECT
                full_name,
                relationship,
                overall_rating,
                comments,
                created_at
            FROM vista_feedback
            WHERE status = 'APPROVED'
              AND publish_consent = TRUE
            ORDER BY created_at DESC
            LIMIT 30
        `);

        return res.json({
            items: result.rows
        });

    } catch (error) {
        console.error("Public reviews error:", error);

        return res.status(500).json({
            error: "Unable to load reviews."
        });
    }
});

// SPA FALLBACK
app.get("*", (req, res) => {
    res.sendFile(path.join(dir, "public", "index.html"));
});

// START SERVER
init()
    .then(() => {
        app.listen(PORT, () => {
            console.log(
                "VISTA AI Feedback running on port " + PORT
            );
        });
    })
    .catch(error => {
        console.error("Server startup failed:", error);
        process.exit(1);
    });
