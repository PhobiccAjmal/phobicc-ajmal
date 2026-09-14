const express = require("express");
const path = require("path");
const crypto = require("crypto");
const cookieParser = require("cookie-parser");
const { createClient } = require("@supabase/supabase-js");

const app = express();

const PORT = Number(process.env.PORT || 10000);

/* =========================
   ENVIRONMENT VARIABLES
========================= */

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY =
  process.env.SUPABASE_SERVICE_ROLE_KEY;

const ADMIN_ID =
  process.env.ADMIN_ID || "Ajmal350";

const ADMIN_PASSWORD =
  process.env.ADMIN_PASSWORD;

const SESSION_SECRET =
  process.env.SESSION_SECRET;


/* =========================
   CHECK ENVIRONMENT
========================= */

if (
  !SUPABASE_URL ||
  !SUPABASE_SERVICE_ROLE_KEY ||
  !ADMIN_PASSWORD ||
  !SESSION_SECRET
) {
  console.error(
    "Missing Render environment variables."
  );

  process.exit(1);
}


/* =========================
   SUPABASE
========================= */

const supabase = createClient(
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  {
    auth: {
      persistSession: false
    }
  }
);


/* =========================
   MIDDLEWARE
========================= */

app.use(
  express.json({
    limit: "2mb"
  })
);

app.use(cookieParser());


/* =========================
   SESSION FUNCTIONS
========================= */

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

    const parts =
      token.split(".");

    if (parts.length !== 2) {
      return false;
    }

    const encoded =
      parts[0];

    const signature =
      parts[1];

    const payload =
      Buffer
        .from(
          encoded,
          "base64url"
        )
        .toString("utf8");

    const expected =
      sign(payload);

    if (
      signature.length !==
      expected.length
    ) {
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

    const payloadParts =
      payload.split(":");

    const id =
      payloadParts[0];

    const created =
      Number(payloadParts[1]);

    const age =
      Date.now() - created;

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


function requireAdmin(
  req,
  res,
  next
) {

  if (
    !validSession(
      req.cookies.admin_session
    )
  ) {

    return res
      .status(401)
      .json({
        error:
          "Unauthorized"
      });

  }

  next();
}


/* =========================
   LOGIN
========================= */

app.post(
  "/api/login",
  (req, res) => {

    const id =
      String(
        req.body.id || ""
      ).trim();

    const password =
      String(
        req.body.password || ""
      );

    if (
      id !== ADMIN_ID ||
      password !==
        ADMIN_PASSWORD
    ) {

      return res
        .status(401)
        .json({
          error:
            "Invalid ID or password."
        });

    }

    const session =
      createSession();

    res.cookie(
      "admin_session",
      session,
      {
        httpOnly: true,
        secure: true,
        sameSite: "lax",
        maxAge:
          7 *
          24 *
          60 *
          60 *
          1000
      }
    );

    res.json({
      ok: true
    });

  }
);


/* =========================
   SESSION CHECK
========================= */

app.get(
  "/api/session",
  (req, res) => {

    res.json({
      loggedIn:
        validSession(
          req.cookies
            .admin_session
        )
    });

  }
);


/* =========================
   LOGOUT
========================= */

app.post(
  "/api/logout",
  (req, res) => {

    res.clearCookie(
      "admin_session"
    );

    res.json({
      ok: true
    });

  }
);


/* =========================
   PUBLIC SUPABASE CONFIG
========================= */

app.get(
  "/api/public-config",
  (req, res) => {

    const SUPABASE_ANON_KEY =
      process.env
        .SUPABASE_ANON_KEY;

    if (
      !SUPABASE_ANON_KEY
    ) {

      return res
        .status(500)
        .json({
          error:
            "SUPABASE_ANON_KEY is missing."
        });

    }

    res.json({
      url:
        SUPABASE_URL,

      anonKey:
        SUPABASE_ANON_KEY
    });

  }
);


/* =========================
   CREATE SIGNED UPLOAD URL
========================= */

app.post(
  "/api/upload-url",
  requireAdmin,
  async (req, res) => {

    try {

      const filename =
        String(
          req.body.filename || ""
        ).trim();

      const contentType =
        String(
          req.body.contentType || ""
        ).trim();


      if (!filename) {

        return res
          .status(400)
          .json({
            error:
              "Filename is required."
          });

      }


      const isImage =
        contentType.startsWith(
          "image/"
        );

      const isVideo =
        contentType.startsWith(
          "video/"
        );


      if (
        !isImage &&
        !isVideo
      ) {

        return res
          .status(400)
          .json({
            error:
              "Only image and video files are allowed."
          });

      }


      let ext =
        path
          .extname(filename)
          .toLowerCase()
          .replace(
            /[^a-z0-9.]/g,
            ""
          )
          .slice(0, 10);


      if (!ext) {

        ext =
          isVideo
            ? ".mp4"
            : ".jpg";

      }


      const storagePath =
        Date.now() +
        "-" +
        crypto
          .randomBytes(10)
          .toString("hex") +
        ext;


      const {
        data,
        error
      } =
        await supabase
          .storage
          .from("media")
          .createSignedUploadUrl(
            storagePath
          );


      if (error) {

        console.error(
          "Signed URL error:",
          error
        );

        return res
          .status(500)
          .json({
            error:
              error.message
          });

      }


      res.json({

        ok: true,

        path:
          storagePath,

        token:
          data.token

      });

    } catch (error) {

      console.error(
        error
      );

      res
        .status(500)
        .json({
          error:
            error.message ||
            "Could not create upload URL."
        });

    }

  }
);


/* =========================
   COMPLETE UPLOAD
========================= */

app.post(
  "/api/complete-upload",
  requireAdmin,
  async (req, res) => {

    try {

      const filename =
        String(
          req.body.filename || ""
        ).trim();


      const storagePath =
        String(
          req.body.storagePath || ""
        ).trim();


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


      const mediaType =
        req.body.mediaType ===
        "video"
          ? "video"
          : "image";


      if (
        !filename ||
        !storagePath
      ) {

        return res
          .status(400)
          .json({
            error:
              "Missing upload information."
          });

      }


      const {
        data,
        error
      } =
        await supabase
          .from("media")
          .insert({
            filename:
              filename,

            storage_path:
              storagePath,

            description:
              description,

            details:
              details,

            media_type:
              mediaType
          })
          .select()
          .single();


      if (error) {

        console.error(
          "Database error:",
          error
        );


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
              error.message
          });

      }


      const publicUrl =
        SUPABASE_URL +
        "/storage/v1/object/public/media/" +
        encodeURIComponent(
          storagePath
        );


      res.json({

        ok: true,

        item: {
          ...data,
          url:
            publicUrl
        }

      });

    } catch (error) {

      console.error(
        error
      );

      res
        .status(500)
        .json({
          error:
            error.message ||
            "Could not save upload."
        });

    }

  }
);


/* =========================
   GET MEDIA
========================= */

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
          .select("*")
          .order(
            "created_at",
            {
              ascending:
                false
            }
          );


      if (error) {

        return res
          .status(500)
          .json({
            error:
              error.message
          });

      }


      const items =
        data.map(
          item => ({

            ...item,

            url:
              SUPABASE_URL +
              "/storage/v1/object/public/media/" +
              encodeURIComponent(
                item.storage_path
              )

          })
        );


      res.json(
        items
      );

    } catch (error) {

      res
        .status(500)
        .json({
          error:
            error.message
        });

    }

  }
);


/* =========================
   DELETE MEDIA
========================= */

app.delete(
  "/api/media/:id",
  requireAdmin,
  async (req, res) => {

    try {

      const id =
        req.params.id;


      const {
        data: item,
        error: findError
      } =
        await supabase
          .from("media")
          .select("*")
          .eq("id", id)
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

        console.error(
          storageError
        );

      }


      const {
        error: deleteError
      } =
        await supabase
          .from("media")
          .delete()
          .eq("id", id);


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
            error.message
        });

    }

  }
);


/* =========================
   STATIC FILES
========================= */

app.use(
  express.static(
    path.join(
      __dirname,
      "public"
    )
  )
);


/* =========================
   ADMIN PAGE
========================= */

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


/* =========================
   ABOUT PAGE
========================= */

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


/* =========================
   HOME / FALLBACK
========================= */

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


/* =========================
   START SERVER
========================= */

app.listen(
  PORT,
  () => {

    console.log(
      `Phobicc.ajmall running on port ${PORT}`
    );

  }
);
