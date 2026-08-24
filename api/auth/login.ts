import { authenticate } from "../../lib/authServerless";

export default function handler(req: any, res: any) {
  if (req.method !== "POST") {
    return res.status(405).json({ success: false, message: "Method not allowed" });
  }
  try {
    const { username, pin, password, device } = req.body || {};
    const secret = pin || password || "";
    const result = authenticate(username, secret, device);
    if (result.success) {
      return res.json({ success: true, token: result.token, user: result.user, message: result.message });
    }
    return res.status(401).json({ success: false, message: result.message });
  } catch (e: any) {
    return res.status(500).json({ success: false, error: e.message });
  }
}
