import axios from "axios";
import { createClient } from "@supabase/supabase-js";

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

export async function fetchProperty(
  objectType,
  objectId,
  propertyName,
  accessToken
) {
  const res = await axios.get(
    `https://api.hubapi.com/crm/v3/objects/${objectType}/${objectId}`,
    {
      headers: { Authorization: `Bearer ${accessToken}` },
    }
  );
  return res.data.properties[propertyName];
}

export async function updateProperty(
  objectType,
  objectId,
  propertyName,
  value,
  accessToken
) {
  await axios.patch(
    `https://api.hubapi.com/crm/v3/objects/${objectType}/${objectId}`,
    { properties: { [propertyName]: value } },
    { headers: { Authorization: `Bearer ${accessToken}` } }
  );
}

export function calculateNewDate(baseDate, amount, unit) {
  if (!baseDate) throw new Error("Base date missing");
  if (isNaN(amount)) throw new Error("Amount must be a number");

  const date = new Date(baseDate);
  const amt = Number(amount);
  const u = unit.toLowerCase();

  switch (u) {
    case "minutes":
      date.setMinutes(date.getMinutes() + amt);
      break;
    case "hours":
      date.setHours(date.getHours() + amt);
      break;
    case "days":
      date.setDate(date.getDate() + amt);
      break;
    case "weeks":
      date.setDate(date.getDate() + amt * 7);
      break;
    case "months":
      date.setMonth(date.getMonth() + amt);
      break;
    default:
      throw new Error(`Invalid unit: ${unit}`);
  }

  return date.toISOString();
}

export async function storeTokensInSupabase(
  userId,
  accessToken,
  refreshToken,
  expiresIn,
  portalId = null
) {
  try {
    let expiresInSeconds = typeof expiresIn === 'number' ? expiresIn : 3600;
    if (expiresInSeconds <= 0) {
      expiresInSeconds = 3600;
    }
    const expiresAt = new Date(Date.now() + expiresInSeconds * 1000).toISOString();

    const originalUserId = String(userId);
    let existingTokens = await getTokensFromSupabase(userId);
    
    let orphanedUserId = null;
    if (portalId !== null && portalId !== undefined) {
      const existingByPortal = await getTokensByPortalId(portalId);
      if (existingByPortal) {
        if (!existingTokens || existingByPortal.user_id !== originalUserId) {
          if (existingTokens && existingByPortal.user_id !== originalUserId) {
            orphanedUserId = originalUserId;
          }
          userId = existingByPortal.user_id;
          existingTokens = existingByPortal;
        }
      }
    }
    
    const tokenData = {
      user_id: String(userId),
      access_token: String(accessToken),
      refresh_token: String(refreshToken),
      expires_at: expiresAt,
      updated_at: new Date().toISOString(),
    };

    if (portalId !== null && portalId !== undefined) {
      tokenData.portal_id = String(portalId);
    } else if (existingTokens && existingTokens.portal_id) {
      tokenData.portal_id = existingTokens.portal_id;
    }

    const { data, error } = await supabase
      .from("hubspot_tokens")
      .upsert(tokenData, {
        onConflict: 'user_id',
        ignoreDuplicates: false
      })
      .select();

    if (error) {
      console.error("Error upserting tokens in Supabase:", error);
      throw error;
    }
    
    if (orphanedUserId && orphanedUserId !== userId) {
      try {
        await deleteTokensFromSupabase(orphanedUserId);
      } catch (deleteError) {
        console.error("Failed to delete orphaned token:", deleteError.message);
      }
    }
    
    return data;
  } catch (error) {
    console.error("Failed to store tokens:", error);
    throw error;
  }
}

export async function getTokensFromSupabase(userId) {
  try {
    const userIdStr = String(userId);
    
    const { data, error } = await supabase
      .from("hubspot_tokens")
      .select("*")
      .eq("user_id", userIdStr)
      .maybeSingle();

    if (error) {
      if (error.code !== "PGRST116") {
        console.error("Error retrieving tokens from Supabase:", error);
        throw error;
      }
      return null;
    }

    if (!data) {
      return null;
    }

    if (data.expires_at && !data.expires_at.endsWith('Z') && !data.expires_at.includes('+')) {
      data.expires_at = new Date(data.expires_at).toISOString();
    }

    return data;
  } catch (error) {
    console.error("Failed to retrieve tokens:", error);
    return null;
  }
}

export async function isTokenExpired(expiresAt) {
  if (!expiresAt) {
    return true;
  }
  
  let expirationDate;
  if (expiresAt instanceof Date) {
    expirationDate = expiresAt;
  } else if (typeof expiresAt === 'string') {
    expirationDate = new Date(expiresAt);
  } else {
    expirationDate = new Date(expiresAt);
  }
  
  if (isNaN(expirationDate.getTime())) {
    return true;
  }
  
  const now = new Date();
  const timeUntilExpiry = expirationDate.getTime() - now.getTime();
  const isExpired = timeUntilExpiry <= 10000;
  
  return isExpired;
}

export async function deleteTokensFromSupabase(userId) {
  try {
    const { error } = await supabase
      .from("hubspot_tokens")
      .delete()
      .eq("user_id", userId);

    if (error) {
      console.error("Error deleting tokens from Supabase:", error);
      throw error;
    }
  } catch (error) {
    console.error("Failed to delete tokens:", error);
    throw error;
  }
}

export async function getAllUsersWithTokens() {
  try {
    const { data, error } = await supabase
      .from("hubspot_tokens")
      .select("user_id")
      .not("refresh_token", "is", null);

    if (error) {
      console.error("Error retrieving users from Supabase:", error);
      throw error;
    }

    return data ? data.map(row => row.user_id) : [];
  } catch (error) {
    console.error("Failed to retrieve users:", error);
    return [];
  }
}

export async function getTokensByPortalId(portalId) {
  try {
    if (!portalId) {
      return null;
    }
    
    const { data, error } = await supabase
      .from("hubspot_tokens")
      .select("*")
      .eq("portal_id", String(portalId))
      .maybeSingle();

    if (error) {
      if (error.code !== "PGRST116") {
        console.error("Error retrieving tokens by portal_id from Supabase:", error);
        throw error;
      }
      return null;
    }

    if (data && data.expires_at && !data.expires_at.endsWith('Z') && !data.expires_at.includes('+')) {
      data.expires_at = new Date(data.expires_at).toISOString();
    }

    return data;
  } catch (error) {
    console.error("Failed to retrieve tokens by portal_id:", error);
    return null;
  }
}
