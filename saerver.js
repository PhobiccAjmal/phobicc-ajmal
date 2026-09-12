const express = require("express");
const path = require("path");
const crypto = require("crypto");
const cookieParser = require("cookie-parser");
const multer = require("multer");
const { createClient } = require("@supabase/supabase-js");

const app = express();

const PORT = Number(process.env.PORT || 10000);

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY =
  process.env.SUPABASE_SERVICE_ROLE_KEY;

const ADMIN_ID = process.env.ADMIN_ID || "Ajmal350";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const SESSION_SECRET = process.env.SESSION_SECRET;


// =========================
// CHECK ENVIRONMENT VARIABLES
// =========================

if (
  !SUPABASE_URL ||
  !SUPABASE_SERVICE_ROLE_KEY ||
  !ADMIN_PASSWORD ||
  !SESSION_SECRET
) {
  console.error("Missing Render environment variables.");
  process.exit(1);
}


// =========================
// SUPABASE
// =========================

const supabase = createClient(
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  {
    auth: {
      persistSession: false
    }
  }
);


// =========================
// EXPRESS
// =========================

app.use(
  express.json({
    limit: "2mb"
  })
);

app.use(cookieParser());


// =========================
// MULTER UPLOAD
// =========================

const upload = multer({
  storage: multer.memoryStorage(),

  limits: {
    fileSize: 100 * 1024 * 1024
  },

  fileFilter: (req, file, cb) => {

    const allowed =
      file.mimetype.startsWith("image/") ||
      file.mimetype.startsWith("video/");

    if (!allowed) {
      return cb(
        new Error(
          "Only image and video files are allowed."
        )
      );
    }

    cb(null, true);
  }
});


// =========================
// LOGIN SYSTEM
// =========================

function sign(value) {
  return crypto
    .createHmac(
      "sha256",
      SESSION_SECRET
    )
    .update(value)
    .digest("hex");
}


function createSession() {

  const payload =
    ADMIN_ID + ":" + Date.now();

  return (
    Buffer
      .from(payload)
      .toString("base64url") +
    "." +
    sign(payload)
  );
}


function validSession(token) {

  try {

    if (!token) {
      return false;
    }

    const parts = token.split(".");

    if (parts.length !== 2) {
      return false;
    }

    const encoded = parts[0];
    const signature = parts[1];

    const payload =
      Buffer
        .from(encoded, "base64url")
        .toString("utf8");

    const expected = sign(payload);

    if (signature.length !== expected.length) {
      return false;
    }

    if (
      !crypto.timingSafeEqual(
        Buffer.from(signature),
        Buffer.from(expected)
      )
    ) {
      return false;
    }

    const parts2 = payload.split(":");

    const id = parts2[0];
    const created = Number(parts2[1]);

    const age = Date.now() - created;

    return (
      id === ADMIN_ID &&
      Number.isFinite(age) &&
      age >= 0 &&
      age <=
        7 *
        24 *
        60 *
        60 *
        1000
    );

  } catch {

    return false;
  }
}


// =========================
// ADMIN PROTECTION
// =========================

function requireAdmin(req, res, next) {

  if (
    !validSession(
      req.cookies.admin_session
    )
  ) {

    return res
      .status(401)
      .json({
        error: "Unauthorized"
      });
  }

  next();
}


// =========================
// PUBLIC MEDIA
// =========================

app.get(
  "/api/media",
  async (req, res) => {

    try {

      const {
        data,
        error
      } =
        await supabase
          .from("media")
          .select(
            "id,filename,storage_path,description,details,media_type,created_at"
          )
          .order(
            "created_at",
            {
              ascending: false
            }
          );

      if (error) {

        return res
          .status(500)
          .json({
            error: error.message
          });
      }

      const items =
        (data || []).map((item) => {

          const url =
            SUPABASE_URL +
            "/storage/v1/object/public/media/" +
            encodeURIComponent(
              item.storage_path
            );

          return {
            ...item,
            url
          };

        });

      res.json(items);

    } catch (error) {

      res
        .status(500)
        .json({
          error:
            error.message ||
            "Could not load media."
        });
    }
  }
);


// =========================
// LOGIN
// =========================

app.post(
  "/api/login",
  (req, res) => {

    const {
      id,
      password
    } = req.body || {};

    if (
      id !== ADMIN_ID ||
      password !== ADMIN_PASSWORD
    ) {

      return res
        .status(401)
        .json({
          error:
            "Invalid ID or password."
        });
    }

    res.cookie(
      "admin_session",
      createSession(),
      {
        httpOnly: true,

        secure:
          process.env.NODE_ENV ===
          "production",

        sameSite: "lax",

        maxAge:
          7 *
          24 *
          60 *
          60 *
          1000,

        path: "/"
      }
    );

    res.json({
      ok: true
    });
  }
);


// =========================
// LOGOUT
// =========================

app.post(
  "/api/logout",
  (req, res) => {

    res.clearCookie(
      "admin_session",
      {
        path: "/"
      }
    );

    res.json({
      ok: true
    });
  }
);


// =========================
// CHECK LOGIN
// =========================

app.get(
  "/api/session",
  (req, res) => {

    res.json({
      loggedIn:
        validSession(
          req.cookies.admin_session
        )
    });
  }
);


// =========================
// UPLOAD PHOTO / VIDEO
// =========================

app.post(
  "/api/upload",
  requireAdmin,
  upload.single("media"),

  async (req, res) => {

    try {

      if (!req.file) {

        return res
          .status(400)
          .json({
            error:
              "Choose a photo or video."
          });
      }


      const description =
        String(
          req.body.description || ""
        )
          .trim()
          .slice(0, 2000);


      const details =
        String(
          req.body.details || ""
        )
          .trim()
          .slice(0, 5000);


      // File extension
      const ext =
        path
          .extname(
            req.file.originalname
          )
          .toLowerCase()
          .replace(
            /[^a-z0-9.]/g,
            ""
          )
          .slice(0, 10);


      // Unique filename
      const fileName =
        Date.now() +
        "-" +
        crypto
          .randomBytes(8)
          .toString("hex") +
        ext;


      const storagePath =
        fileName;


      // =========================
      // UPLOAD TO SUPABASE STORAGE
      // =========================

      const {
        error: uploadError
      } =
        await supabase
          .storage
          .from("media")
          .upload(
            storagePath,
            req.file.buffer,
            {
              contentType:
                req.file.mimetype,

              upsert: false
            }
          );


      if (uploadError) {

        return res
          .status(500)
          .json({
            error:
              uploadError.message
          });
      }


      // =========================
      // SAVE INFORMATION TO DATABASE
      // =========================

      const {
        data,
        error: dbError
      } =
        await supabase
          .from("media")
          .insert({
            filename:
              req.file.originalname,

            storage_path:
              storagePath,

            description,

            details,

            media_type:
              req.file.mimetype
                .startsWith("video/")
                ? "video"
                : "image"
          })
          .select()
          .single();


      // If database fails,
      // delete uploaded file
      if (dbError) {

        await supabase
          .storage
          .from("media")
          .remove([
            storagePath
          ]);

        return res
          .status(500)
          .json({
            error:
              dbError.message
          });
      }


      // =========================
      // RETURN UPLOADED MEDIA
      // =========================

      res.json({

        ok: true,

        item: {

          ...data,

          url:
            SUPABASE_URL +
            "/storage/v1/object/public/media/" +
            encodeURIComponent(
              storagePath
            )
        }
      });


    } catch (error) {

      res
        .status(500)
        .json({
          error:
            error.message ||
            "Upload failed."
        });
    }
  }
);


// =========================
// DELETE MEDIA
// =========================

app.delete(
  "/api/media/:id",
  requireAdmin,

  async (req, res) => {

    try {

      const id =
        Number(
          req.params.id
        );


      if (
        !Number.isInteger(id)
      ) {

        return res
          .status(400)
          .json({
            error:
              "Invalid media ID."
          });
      }


      // Find media record
      const {
        data: item,
        error: findError
      } =
        await supabase
          .from("media")
          .select(
            "id,storage_path"
          )
          .eq(
            "id",
            id
          )
          .single();


      if (
        findError ||
        !item
      ) {

        return res
          .status(404)
          .json({
            error:
              "Media not found."
          });
      }


      // Delete file from Storage
      const {
        error: storageError
      } =
        await supabase
          .storage
          .from("media")
          .remove([
            item.storage_path
          ]);


      if (storageError) {

        return res
          .status(500)
          .json({
            error:
              storageError.message
          });
      }


      // Delete database record
      const {
        error: deleteError
      } =
        await supabase
          .from("media")
          .delete()
          .eq(
            "id",
            id
          );


      if (deleteError) {

        return res
          .status(500)
          .json({
            error:
              deleteError.message
          });
      }


      res.json({
        ok: true
      });


    } catch (error) {

      res
        .status(500)
        .json({
          error:
            error.message ||
            "Delete failed."
        });
    }
  }
);


// =========================
// WEBSITE FILES
// =========================

app.use(
  express.static(
    path.join(
      __dirname,
      "public"
    )
  )
);


// =========================
// ADMIN PAGE
// =========================

app.get(
  "/admin",
  (req, res) => {

    res.sendFile(
      path.join(
        __dirname,
        "public",
        "admin.html"
      )
    );
  }
);


// =========================
// ABOUT PAGE
// =========================

app.get(
  "/about",
  (req, res) => {

    res.sendFile(
      path.join(
        __dirname,
        "public",
        "about.html"
      )
    );
  }
);


// =========================
// DEFAULT PAGE
// =========================

app.use(
  (req, res) => {

    res.sendFile(
      path.join(
        __dirname,
        "public",
        "index.html"
      )
    );
  }
);


// =========================
// ERROR HANDLER
// =========================

app.use(
  (err, req, res, next) => {

    if (
      err instanceof multer.MulterError
    ) {

      if (
        err.code ===
        "LIMIT_FILE_SIZE"
      ) {

        return res
          .status(413)
          .json({
            error:
              "Maximum file size is 100 MB."
          });
      }

      return res
        .status(400)
        .json({
          error:
            err.message
        });
    }

    res
      .status(400)
      .json({
        error:
          err.message ||
          "Request failed."
      });
  }
);


// =========================
// START SERVER
// =========================

app.listen(
  PORT,
  () => {

    console.log(
      "Phobicc.ajmall running on port " +
      PORT
    );

  }
);