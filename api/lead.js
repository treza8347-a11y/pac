
export default async function handler(req, res) {
  // Autoriser uniquement POST
  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      message: "Méthode non autorisée."
    });
  }

  try {
    const body = req.body || {};

    // --------------------------------------------------
    // 1. HONEYPOT
    // --------------------------------------------------

    if (body.website && String(body.website).trim() !== "") {
      return res.status(400).json({
        success: false,
        message: "Requête refusée."
      });
    }

    // --------------------------------------------------
    // 2. TURNSTILE
    // --------------------------------------------------

    const turnstileToken = body["cf-turnstile-response"];

    if (!turnstileToken) {
      return res.status(400).json({
        success: false,
        message: "Vérification anti-robot manquante."
      });
    }

    const turnstileSecret = process.env.TURNSTILE_SECRET;

    if (!turnstileSecret) {
      console.error("TURNSTILE_SECRET manquante.");

      return res.status(500).json({
        success: false,
        message: "Configuration serveur incorrecte."
      });
    }

   const ip =
  req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
  req.headers["x-real-ip"]?.trim() ||
  req.headers["x-vercel-forwarded-for"]?.trim() ||
  req.socket?.remoteAddress ||
  "";

    const verificationResponse = await fetch(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          secret: turnstileSecret,
          response: turnstileToken,
          remoteip: ip || undefined
        })
      }
    );

    const verification = await verificationResponse.json();

    if (!verification.success) {
      console.warn(
        "Turnstile refusé:",
        verification["error-codes"] || []
      );

      return res.status(403).json({
        success: false,
        message: "La vérification anti-robot a échoué."
      });
    }

    // --------------------------------------------------
    // 3. VALIDATION DES CHAMPS
    // --------------------------------------------------

    const requiredFields = [
      "Prenom",
      "Nom",
      "Telephone",
      "Email",
      "Adresse",
      "CodePostal",
      "Ville",
      "TypeLogement",
      "Statut",
      "Surface",
      "ChauffageActuel",
      "RevenuFiscal",
      "NombrePersonnes"
    ];

    for (const field of requiredFields) {
      if (
        body[field] === undefined ||
        body[field] === null ||
        String(body[field]).trim() === ""
      ) {
        return res.status(400).json({
          success: false,
          message: "Veuillez remplir tous les champs obligatoires."
        });
      }
    }

    // --------------------------------------------------
    // 4. VALIDATION EMAIL
    // --------------------------------------------------

    const email = String(body.Email).trim();

    const emailRegex =
      /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        message: "Adresse email invalide."
      });
    }

    // --------------------------------------------------
    // 5. VALIDATION CODE POSTAL
    // --------------------------------------------------

    const codePostal = String(body.CodePostal).trim();

    if (!/^\d{5}$/.test(codePostal)) {
      return res.status(400).json({
        success: false,
        message: "Code postal invalide."
      });
    }

    // --------------------------------------------------
    // 6. VALIDATION CONSENTEMENT
    // --------------------------------------------------

    if (
      body.Consentement !== true &&
      body.Consentement !== "true" &&
      body.Consentement !== "Oui" &&
      body.Consentement !== "on"
    ) {
      return res.status(400).json({
        success: false,
        message: "Le consentement est obligatoire."
      });
    }

    // --------------------------------------------------
    // 7. SECRET ENTRE VERCEL ET APPS SCRIPT
    // --------------------------------------------------

    const appsScriptSecret =
      process.env.APPS_SCRIPT_SECRET;

    if (!appsScriptSecret) {
      console.error("APPS_SCRIPT_SECRET manquante.");

      return res.status(500).json({
        success: false,
        message: "Configuration serveur incorrecte."
      });
    }

    // --------------------------------------------------
    // 8. PRÉPARATION DES DONNÉES
    // --------------------------------------------------

    const data = {
      Prenom: String(body.Prenom).trim(),
      Nom: String(body.Nom).trim(),
      Telephone: String(body.Telephone).trim(),
      Email: email,
      Adresse: String(body.Adresse).trim(),
      CodePostal: codePostal,
      Ville: String(body.Ville).trim(),
      TypeLogement: String(body.TypeLogement).trim(),
      Statut: String(body.Statut).trim(),
      Surface: String(body.Surface).trim(),
      ChauffageActuel: String(body.ChauffageActuel).trim(),
      RevenuFiscal: String(body.RevenuFiscal).trim(),
     NombrePersonnes: String(body.NombrePersonnes).trim(),
      AdresseIP: ip || "IP_NON_DETECTEE",
      Consentement: true,

      _secret: appsScriptSecret
    };

    // --------------------------------------------------
    // 9. ENVOI À GOOGLE APPS SCRIPT
    // --------------------------------------------------

    const appsScriptUrl =
      process.env.APPS_SCRIPT_URL;

    if (!appsScriptUrl) {
      console.error("APPS_SCRIPT_URL manquante.");

      return res.status(500).json({
        success: false,
        message: "Configuration serveur incorrecte."
      });
    }

    const googleResponse = await fetch(
     appsScriptUrl + "?AdresseIP=" + encodeURIComponent(ip),
      {
        method: "POST",
        headers: {
          "Content-Type": "text/plain;charset=utf-8"
        },
        body: JSON.stringify(data)
      }
    );

    const googleText = await googleResponse.text();

    let googleResult = {};

    try {
      googleResult = JSON.parse(googleText);
    } catch (error) {
      console.error(
        "Réponse Apps Script non JSON:",
        googleText
      );
    }

    // --------------------------------------------------
    // 10. VÉRIFICATION DE LA RÉPONSE GOOGLE
    // --------------------------------------------------

    if (
      googleResult.result !== "success"
    ) {
      console.error(
        "Apps Script a refusé la demande:",
        googleResult
      );

      return res.status(502).json({
        success: false,
        message:
          "Impossible d'enregistrer votre demande pour le moment."
      });
    }

    // --------------------------------------------------
    // 11. SUCCÈS
    // --------------------------------------------------

    return res.status(200).json({
      success: true,
      message: "Demande enregistrée."
    });

  } catch (error) {
    console.error("Erreur API lead:", error);

    return res.status(500).json({
      success: false,
      message:
        "Une erreur est survenue. Veuillez réessayer."
    });
  }
}
