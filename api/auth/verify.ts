import { verifyToken, getSessionInfo } from "../../lib/authServerless";

export default function handler(req: any, res: any) {
  if (req.method !== "GET") {
    return res.status(405).json({ success: false, message: "Method not allowed" });
  }
  try {
    const authHeader = req.headers.authorization || "";
    const token = authHeader.startsWith("Bearer ") ? authHeader.substring(7) : (req.query.token as string || "");
    const result = verifyToken(token);
    if (result.valid) {
      const sessionInfo = getSessionInfo();
      return res.json({ success: true, authenticated: true, user: result.user, session: sessionInfo });
    }
    return res.status(401).json({ success: false, authenticated: false, message: "Session expired or invalid" });
  } catch (e: any) {
    return res.status(500).json({ success: false, error: e.message });
  }
}
