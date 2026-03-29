const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

// =========================
// CONFIG ADMIN
// =========================
const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASS = process.env.ADMIN_PASS || "123456";

app.use(cors());
app.use(express.json());

const KEYS_FILE = path.join(__dirname, "keys.json");
const DEVICES_FILE = path.join(__dirname, "devices.json");

function ensureFile(filePath, defaultData) {
  if (!fs.existsSync(filePath)) {
    fs.writeFileSync(filePath, JSON.stringify(defaultData, null, 2), "utf8");
  }
}

function readJSON(filePath, fallback = []) {
  try {
    if (!fs.existsSync(filePath)) return fallback;
    const raw = fs.readFileSync(filePath, "utf8").trim();
    if (!raw) return fallback;
    return JSON.parse(raw);
  } catch (error) {
    console.error("Erro ao ler arquivo:", filePath, error);
    return fallback;
  }
}

function saveJSON(filePath, data) {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), "utf8");
}

function generateKey() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const block = () =>
    Array.from({ length: 4 }, () => chars[Math.floor(Math.random() * chars.length)]).join("");
  return `ES-${block()}-${block()}-${block()}`;
}

function addDays(days) {
  const date = new Date();
  date.setDate(date.getDate() + days);
  return date.toISOString();
}

function getStatus(keyObj) {
  if (!keyObj) return "desconhecida";
  if (keyObj.revoked) return "revogada";
  if (new Date(keyObj.expiresAt) < new Date()) return "expirada";
  if (keyObj.active) return "ativa";
  return "disponível";
}

function isAuthorized(req) {
  const user = req.headers["x-admin-user"];
  const pass = req.headers["x-admin-pass"];
  return user === ADMIN_USER && pass === ADMIN_PASS;
}

function requireAdmin(req, res, next) {
  if (!isAuthorized(req)) {
    return res.status(401).json({
      success: false,
      message: "Não autorizado."
    });
  }
  next();
}

// =========================
// ANTI-BYPASS BÁSICO
// =========================
app.use((req, res, next) => {
  if (req.path === "/" || req.path === "/admin" || req.path === "/admin-login") {
    return next();
  }

  const ua = String(req.headers["user-agent"] || "").toLowerCase();

  if (
    ua.includes("postman") ||
    ua.includes("insomnia") ||
    ua.includes("curl")
  ) {
    return res.status(403).json({
      success: false,
      message: "Acesso bloqueado."
    });
  }

  next();
});

ensureFile(KEYS_FILE, []);
ensureFile(DEVICES_FILE, []);

app.get("/", (req, res) => {
  res.json({
    success: true,
    status: "online",
    message: "Servidor de licenças rodando"
  });
});

app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "admin.html"));
});

app.post("/admin-login", (req, res) => {
  try {
    const { username, password } = req.body;

    if (username === ADMIN_USER && password === ADMIN_PASS) {
      return res.json({
        success: true,
        message: "Login realizado com sucesso."
      });
    }

    return res.status(401).json({
      success: false,
      message: "Usuário ou senha inválidos."
    });
  } catch (error) {
    console.error("Erro em /admin-login:", error);
    res.status(500).json({
      success: false,
      message: "Erro ao fazer login."
    });
  }
});

app.post("/generate-key", requireAdmin, (req, res) => {
  try {
    const days = Math.max(1, Number(req.body.days) || 30);
    const keys = readJSON(KEYS_FILE, []);

    let newKey = generateKey();
    while (keys.some((k) => k.key === newKey)) {
      newKey = generateKey();
    }

    const keyData = {
      id: crypto.randomUUID(),
      key: newKey,
      createdAt: new Date().toISOString(),
      expiresAt: addDays(days),
      active: false,
      usedBy: null,
      activatedAt: null,
      revoked: false
    };

    keys.push(keyData);
    saveJSON(KEYS_FILE, keys);

    res.json({
      success: true,
      message: "Key gerada com sucesso.",
      keyData: {
        ...keyData,
        status: getStatus(keyData)
      }
    });
  } catch (error) {
    console.error("Erro em /generate-key:", error);
    res.status(500).json({
      success: false,
      message: "Erro ao gerar key."
    });
  }
});

app.post("/activate-key", (req, res) => {
  try {
    const { key, deviceId } = req.body;

    if (!key || !deviceId) {
      return res.status(400).json({
        success: false,
        message: "Key e deviceId são obrigatórios."
      });
    }

    const keys = readJSON(KEYS_FILE, []);
    const devices = readJSON(DEVICES_FILE, []);

    const foundKey = keys.find((k) => k.key === key);

    if (!foundKey) {
      return res.status(404).json({
        success: false,
        message: "Key não encontrada."
      });
    }

    if (foundKey.revoked) {
      return res.status(403).json({
        success: false,
        message: "Essa key foi revogada."
      });
    }

    if (new Date(foundKey.expiresAt) < new Date()) {
      return res.status(403).json({
        success: false,
        message: "Key expirada."
      });
    }

    if (foundKey.active && foundKey.usedBy && foundKey.usedBy !== deviceId) {
      return res.status(403).json({
        success: false,
        message: "Essa key já está em uso em outro dispositivo."
      });
    }

    foundKey.active = true;
    foundKey.usedBy = deviceId;
    foundKey.activatedAt = foundKey.activatedAt || new Date().toISOString();

    const existingDevice = devices.find((d) => d.deviceId === deviceId);

    if (!existingDevice) {
      devices.push({
        deviceId,
        key,
        activatedAt: new Date().toISOString()
      });
    } else {
      existingDevice.key = key;
      existingDevice.activatedAt = existingDevice.activatedAt || new Date().toISOString();
    }

    saveJSON(KEYS_FILE, keys);
    saveJSON(DEVICES_FILE, devices);

    res.json({
      success: true,
      message: "Key ativada com sucesso.",
      data: {
        key: foundKey.key,
        deviceId,
        expiresAt: foundKey.expiresAt,
        status: getStatus(foundKey)
      }
    });
  } catch (error) {
    console.error("Erro em /activate-key:", error);
    res.status(500).json({
      success: false,
      message: "Erro ao ativar key."
    });
  }
});

app.post("/check-access", (req, res) => {
  try {
    const { key, deviceId } = req.body;

    if (!key || !deviceId) {
      return res.status(400).json({
        success: false,
        message: "Key e deviceId são obrigatórios."
      });
    }

    const keys = readJSON(KEYS_FILE, []);
    const foundKey = keys.find((k) => k.key === key);

    if (!foundKey) {
      return res.status(404).json({
        success: false,
        message: "Key inválida."
      });
    }

    if (foundKey.revoked) {
      return res.status(403).json({
        success: false,
        message: "Essa key foi revogada."
      });
    }

    if (!foundKey.active) {
      return res.status(403).json({
        success: false,
        message: "Key ainda não foi ativada."
      });
    }

    if (new Date(foundKey.expiresAt) < new Date()) {
      return res.status(403).json({
        success: false,
        message: "Key expirada."
      });
    }

    if (foundKey.usedBy !== deviceId) {
      return res.status(403).json({
        success: false,
        message: "Essa key pertence a outro dispositivo."
      });
    }

    res.json({
      success: true,
      message: "Acesso liberado.",
      data: {
        key: foundKey.key,
        deviceId,
        expiresAt: foundKey.expiresAt,
        status: getStatus(foundKey)
      }
    });
  } catch (error) {
    console.error("Erro em /check-access:", error);
    res.status(500).json({
      success: false,
      message: "Erro ao verificar acesso."
    });
  }
});

app.get("/keys", requireAdmin, (req, res) => {
  try {
    const keys = readJSON(KEYS_FILE, []);
    const mapped = keys
      .map((k) => ({
        ...k,
        status: getStatus(k)
      }))
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

    res.json({
      success: true,
      total: mapped.length,
      keys: mapped
    });
  } catch (error) {
    console.error("Erro em /keys:", error);
    res.status(500).json({
      success: false,
      message: "Erro ao listar keys."
    });
  }
});

app.post("/revoke-key", requireAdmin, (req, res) => {
  try {
    const { key } = req.body;

    if (!key) {
      return res.status(400).json({
        success: false,
        message: "Informe a key."
      });
    }

    const keys = readJSON(KEYS_FILE, []);
    const foundKey = keys.find((k) => k.key === key);

    if (!foundKey) {
      return res.status(404).json({
        success: false,
        message: "Key não encontrada."
      });
    }

    foundKey.revoked = true;
    saveJSON(KEYS_FILE, keys);

    res.json({
      success: true,
      message: "Key revogada com sucesso."
    });
  } catch (error) {
    console.error("Erro em /revoke-key:", error);
    res.status(500).json({
      success: false,
      message: "Erro ao revogar key."
    });
  }
});

app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
