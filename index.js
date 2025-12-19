require("dotenv").config();
const express = require("express");
const request = require("request-promise-native");
const session = require("express-session");
const opn = require("open");
const crypto = require("crypto");
const {
  fetchProperty,
  updateProperty,
  calculateNewDate,
  getTokensFromSupabase,
  storeTokensInSupabase,
  getAllUsersWithTokens,
  isTokenExpired,
} = require("./helper");
const app = express();
const axios = require("axios");
const PORT = process.env.PORT || 3000;

if (!process.env.CLIENT_ID || !process.env.CLIENT_SECRET) {
  throw new Error(
    "Missing CLIENT_ID or CLIENT_SECRE or SMS_TOKEN environment variable."
  );
}

const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
let SCOPES = [
  "oauth",
  "crm.objects.contacts.read",
  "crm.objects.contacts.write",
  "crm.objects.companies.read",
  "crm.objects.deals.read",
  "tickets",
  "crm.objects.companies.write",
  "crm.objects.deals.write",
].join(" ");

if (process.env.SCOPE) {
  SCOPES = process.env.SCOPE.split(/ |, ?|%20/).join(" ");
}

const REDIRECT_URI =
  process.env.REDIRECT_URI || `http://localhost:${PORT}/oauth-callback`;

const SESSION_SECRET =
  process.env.SESSION_SECRET || Math.random().toString(36).substring(2);
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);

app.use(
  express.json({
    verify: (req, res, buf) => {
      req.rawBody = buf.toString("utf8");
    },
  })
);

app.use((req, res, next) => {
  res.setHeader("ngrok-skip-browser-warning", "true");
  next();
});

function isValidHubspotRequest(req) {
  const signatureHeader = req.headers["x-hubspot-signature-v3"] || "";
  const timestampHeader = req.headers["x-hubspot-request-timestamp"] || "";

  if (!signatureHeader || !timestampHeader) {
    return false;
  }

  const MAX_ALLOWED_TIMESTAMP = 300000;
  const currentTime = Date.now();
  const timestamp = parseInt(timestampHeader, 10);

  if (currentTime - timestamp > MAX_ALLOWED_TIMESTAMP) {
    return false;
  }

  const uri = `https://${req.hostname}${req.url}`;
  const rawString = `${req.method}${uri}${JSON.stringify(
    req.body
  )}${timestampHeader}`;

  const hashedString = crypto
    .createHmac("sha256", CLIENT_SECRET)
    .update(rawString)
    .digest("base64");

  const sigBuf = Buffer.from(signatureHeader);
  const hashBuf = Buffer.from(hashedString);

  if (sigBuf.length !== hashBuf.length) {
    return false;
  }

  return crypto.timingSafeEqual(sigBuf, hashBuf);
}

const authUrl =
  "https://app.hubspot.com/oauth/authorize" +
  `?client_id=${encodeURIComponent(CLIENT_ID)}` +
  `&scope=${encodeURIComponent(SCOPES)}` +
  `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}`;

app.get("/install", (req, res) => {
  res.redirect(authUrl);
});

app.get("/oauth-callback", async (req, res) => {
  if (req.query.code) {
    const authCodeProof = {
      grant_type: "authorization_code",
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      redirect_uri: REDIRECT_URI,
      code: req.query.code,
    };

    const tokenResult = await exchangeForTokens(req.sessionID, authCodeProof);

    if (tokenResult.message) {
      console.error("Error exchanging tokens:", tokenResult.message);
      if (req.query.returnUrl) {
        return res.redirect(req.query.returnUrl);
      }
      return res.redirect(`/error?msg=${tokenResult.message}`);
    }

    let portalId = null;
    try {
      const accessToken = await getAccessToken(req.sessionID);
      if (accessToken) {
        const portalInfo = await request.get(
          "https://api.hubapi.com/integrations/v1/me",
          {
            headers: {
              Authorization: `Bearer ${accessToken}`,
              "Content-Type": "application/json",
            },
          }
        );
        const portalData = JSON.parse(portalInfo);
        portalId = portalData.portalId;

        const tokens = await getTokensFromSupabase(req.sessionID);
        if (tokens) {
          await storeTokensInSupabase(
            req.sessionID,
            tokens.access_token,
            tokens.refresh_token,
            3600,
            portalId
          );
        }
      }
    } catch (portalError) {
      console.error("Could not retrieve portal ID:", portalError.message);
    }

    const returnUrl = req.query.returnUrl;
    if (returnUrl) {
      return res.redirect(returnUrl);
    } else if (portalId) {
      return res.redirect(
        `https://app.hubspot.com/connected-apps/${portalId}/installed`
      );
    } else {
      return res.redirect("https://app.hubspot.com/apps");
    }
  } else {
    if (req.query.returnUrl) {
      return res.redirect(req.query.returnUrl);
    }
    return res.redirect("https://app.hubspot.com/apps");
  }
});

app.get("/", async (req, res) => {
  res.setHeader("Content-Type", "text/html");
  res.write(`<h2>HubSpot OAuth 2.0 Quickstart App</h2>`);

  const authorized = await isAuthorized(req.sessionID);
  if (authorized) {
    const accessToken = await getAccessToken(req.sessionID);
    res.write(`<h4>Access token: ${accessToken || "null"}</h4>`);

    if (accessToken) {
      try {
        const contact = await getContact(accessToken);
        displayContactName(res, contact);
      } catch (error) {
        res.write(
          `<p style="color: red;">Error retrieving contact: ${error.message}</p>`
        );
      }
    } else {
      res.write(
        `<p style="color: orange;">Access token is null. Please <a href="/install">reinstall the app</a>.</p>`
      );
    }
  } else {
    res.write(`<a href="/install"><h3>Install the app</h3></a>`);
  }
  res.end();
});

const exchangeForTokens = async (userId, exchangeProof) => {
  try {
    const responseBody = await request.post(
      "https://api.hubapi.com/oauth/v1/token",
      {
        form: exchangeProof,
      }
    );

    const tokens = JSON.parse(responseBody);

    await storeTokensInSupabase(
      userId,
      tokens.access_token,
      tokens.refresh_token,
      tokens.expires_in,
      null
    );

    return tokens.access_token;
  } catch (e) {
    console.error(
      `Error exchanging ${exchangeProof.grant_type} for access token`
    );
    console.error(e.response ? e.response.body : e.message);
    return e.response ? JSON.parse(e.response.body) : { message: e.message };
  }
};

const refreshAccessToken = async (userId) => {
  try {
    const tokenData = await getTokensFromSupabase(userId);

    if (!tokenData || !tokenData.refresh_token) {
      throw new Error("No refresh token found for user");
    }

    const refreshTokenProof = {
      grant_type: "refresh_token",
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      redirect_uri: REDIRECT_URI,
      refresh_token: tokenData.refresh_token,
    };

    return await exchangeForTokens(userId, refreshTokenProof);
  } catch (error) {
    console.error("Error refreshing access token:", error);
    throw error;
  }
};

const getAccessToken = async (userId) => {
  try {
    const tokenData = await getTokensFromSupabase(userId);

    if (!tokenData) {
      return null;
    }

    if (await isTokenExpired(tokenData.expires_at)) {
      return await refreshAccessToken(userId);
    }

    return tokenData.access_token;
  } catch (error) {
    console.error("Error getting access token:", error);
    return null;
  }
};

const isAuthorized = async (userId) => {
  try {
    const tokenData = await getTokensFromSupabase(userId);
    return tokenData !== null && tokenData.refresh_token !== null;
  } catch (error) {
    console.error("Error checking authorization:", error);
    return false;
  }
};

const getContact = async (accessToken) => {
  if (!accessToken) {
    throw new Error("Access token is missing. Please install the app first.");
  }

  try {
    const headers = {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    };
    const result = await request.get(
      "https://api.hubapi.com/contacts/v1/lists/all/contacts/all?count=1",
      {
        headers: headers,
      }
    );

    return JSON.parse(result).contacts[0];
  } catch (e) {
    console.error("Unable to retrieve contact");
    if (e.response && e.response.body) {
      return JSON.parse(e.response.body);
    }
    throw new Error(e.message || "Failed to retrieve contact");
  }
};

const displayContactName = (res, contact) => {
  if (contact.status === "error") {
    res.write(
      `<p>Unable to retrieve contact! Error Message: ${contact.message}</p>`
    );
    return;
  }
  const { firstname, lastname } = contact.properties;
  res.write(`<p>Contact name: ${firstname.value} ${lastname.value}</p>`);
};

app.get("/error", (req, res) => {
  res.setHeader("Content-Type", "text/html");
  res.write(`<h4>Error: ${req.query.msg}</h4>`);
  res.end();
});

app.post("/api/contacts/:contactId/update-property", async (req, res) => {
  const hasSignature = req.headers["x-hubspot-signature-v3"];
  if (hasSignature && !isValidHubspotRequest(req)) {
    return res.status(401).send("Invalid HubSpot signature");
  }

  try {
    const contactId = req.params.contactId;
    const { propertyName, propertyValue } = req.body;

    if (!propertyName || propertyValue === undefined) {
      return res.status(400).json({
        error: "Missing required fields",
        required: ["propertyName", "propertyValue"],
      });
    }

    const userIds = await getAllUsersWithTokens();
    if (userIds.length === 0) {
      return res.status(401).json({
        error: "No authorized users found. Please install the app first.",
      });
    }

    const userId = userIds[0];
    const accessToken = await getAccessToken(userId);

    if (!accessToken) {
      return res.status(401).json({
        error: "Unable to get access token",
      });
    }

    const updateResponse = await request.patch(
      `https://api.hubapi.com/crm/v3/objects/contacts/${contactId}`,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json",
        },
        json: {
          properties: {
            [propertyName]: propertyValue,
          },
        },
      }
    );

    return res.status(200).json({
      success: true,
      message: "Contact property updated successfully",
      data: updateResponse,
    });
  } catch (error) {
    console.error("Error updating contact property:", error.message);
    if (error.response) {
      return res.status(error.response.statusCode || 500).json({
        error: "Failed to update contact property",
        details: error.response.body,
      });
    }
    return res.status(500).json({
      error: "Internal server error",
      message: error.message,
    });
  }
});

app.post("/api/get-properties", async (req, res) => {
  try {
    const { inputFields, fetchOptions } = req.body;

    let targetObjects = [];

    if (inputFields && inputFields.widgetName) {
      const field = inputFields.widgetName;

      if (field.type === "STATIC_VALUE") {
        const value = field.value;
        targetObjects = Array.isArray(value) ? value : [value];
      } else if (field.type === "OBJECT_PROPERTY") {
        targetObjects = [field.propertyName];
      }
    }

    if (targetObjects.length === 0) {
      targetObjects = ["Company", "Contact", "Deal", "Ticket"];
    }

    const userIds = await getAllUsersWithTokens();
    if (userIds.length === 0) {
      return res.status(401).json({
        options: [],
        after: "",
        searchable: false,
        error:
          "App not installed. Please install the app first by visiting /install endpoint.",
        installUrl: `/install`,
      });
    }

    const userId = userIds[0];
    const accessToken = await getAccessToken(userId);

    if (!accessToken) {
      return res.status(401).json({
        options: [],
        after: "",
        searchable: false,
        error: "Authentication failed",
      });
    }

    const objectTypeMap = {
      Company: "companies",
      Contact: "contacts",
      Deal: "deals",
      Ticket: "tickets",
    };

    const allResults = [];

    for (const targetObject of targetObjects) {
      const objectType = objectTypeMap[targetObject];

      if (!objectType) {
        continue;
      }

      try {
        const responseBody = await request.get(
          `https://api.hubapi.com/crm/v3/properties/${objectType}`,
          {
            headers: {
              Authorization: `Bearer ${accessToken}`,
            },
          }
        );

        const response = JSON.parse(responseBody);

        const properties = response.results
          .filter((prop) => {
            const isDateProperty =
              prop.type === "date" || prop.type === "datetime";

            if (isDateProperty && fetchOptions && fetchOptions.q) {
              const searchTerm = fetchOptions.q.toLowerCase();
              const label = (prop.label || prop.name).toLowerCase();
              return label.includes(searchTerm);
            }

            return isDateProperty;
          })
          .map((prop) => ({
            value: `${prop.name}`,
            label: `${prop.label || prop.name}`,
          }));

        allResults.push(...properties);
      } catch (objectError) {
        console.error(
          `Error fetching properties for ${objectType}:`,
          objectError.message
        );
      }
    }

    allResults.sort((a, b) => a.label.localeCompare(b.label));

    res.json({
      options: allResults,
      after: "",
      searchable: true,
    });
  } catch (error) {
    console.error("Error fetching properties:", error.message);
    if (error.response) {
      console.error("Response data:", error.response.data);
      console.error("Response status:", error.response.status);
    }
    res.status(500).json({
      options: [],
      after: "",
      searchable: false,
      error: "Failed to fetch properties",
    });
  }
});
app.post("/api/workflow-date-calculator", async (req, res) => {
  try {
    console.log(req.body);
    const objectId = req.body.object.objectId;
    const objectType = req.body.object.objectType.toLowerCase() + "s";
    const fields = req.body.inputFields;

    const propertyToRead = fields.property_to_read_dynamic;
    const propertyToSet = fields["property_to_set"]
      .toLowerCase()
      .replace(/\s+/g, "");
    const amount = parseInt(fields["amount"]);
    const unit = fields["unit"];

    const userIds = await getAllUsersWithTokens();
    if (userIds.length === 0) {
      return res.status(401).json({
        options: [],
        after: "",
        searchable: false,
        error:
          "App not installed. Please install the app first by visiting /install endpoint.",
        installUrl: `/install`,
      });
    }

    const userId = userIds[0];
    const accessToken = await getAccessToken(userId);

    const currentDate = await fetchProperty(
      objectType,
      objectId,
      propertyToRead,
      accessToken
    );

    const newDate = calculateNewDate(currentDate, amount, unit);

    await updateProperty(
      objectType,
      objectId,
      propertyToSet,
      newDate,
      accessToken
    );

    console.log({
      outputFields: {
        [propertyToSet]: newDate,
      },
    });

    res.json({
      outputFields: {
        [propertyToSet]: newDate,
      },
    });
  } catch (err) {
    console.error("Workflow action error:", err);
    res.status(500).json({ message: "Error processing workflow action" });
  }
});

app.post("/api/get-object-properties", async (req, res) => {
  try {
    const { inputFields } = req.body;
    const objectType =
      inputFields?.["target_object"]?.value ||
      inputFields?.["target object"]?.value;

    if (!objectType) {
      return res.json({ options: [] });
    }

    const objectTypeMap = {
      contact: "contacts",
      company: "companies",
      deal: "deals",
      ticket: "tickets",
      Contact: "contacts",
      Company: "companies",
      Deal: "deals",
      Ticket: "tickets",
    };

    const hubspotObjectType = objectTypeMap[objectType] || objectType;
    const userIds = await getAllUsersWithTokens();
    if (userIds.length === 0) {
      return res.status(401).json({
        options: [],
        after: "",
        searchable: false,
        error:
          "App not installed. Please install the app first by visiting /install endpoint.",
        installUrl: `/install`,
      });
    }

    const userId = userIds[0];
    const accessToken = await getAccessToken(userId);

    // Fetch properties from HubSpot API
    const response = await axios.get(
      `https://api.hubapi.com/crm/v3/properties/${hubspotObjectType}`,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json",
        },
      }
    );
    const dateProperties = response.data.results
      .filter((prop) => {
        // must be date/datetime
        if (prop.type !== "date" && prop.type !== "datetime") {
          return false;
        }

        const meta = prop.modificationMetadata;

        // must explicitly allow value updates
        return meta?.readOnlyValue === false;
      })
      .map((prop) => ({
        label: prop.label,
        value: prop.name,
      }));

    res.json({ options: dateProperties });
  } catch (error) {
    console.error("Error fetching properties:", error.message);
    res.json({
      options: [],
      error: error.message,
    });
  }
});
app.listen(PORT, () => console.log(`Starting app on port ${PORT}`));

if (process.env.NODE_ENV !== "production" && !process.env.FLY_APP_NAME) {
  opn(`http://localhost:${PORT}`);
}
