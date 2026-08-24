import { getSessionInfo } from "../../lib/authServerless";

export default function handler(req: any, res: any) {
  if (req.method !== "GET") {
    return res.status(405).json({ success: false, message: "Method not allowed" });
  }
  try {
    const sessionInfo = getSessionInfo();
    return res.json({ success: true, session: sessionInfo });
  } catch (e: any) {
    return res.status(500).json({ success: false, error: e.message });
  }
}
