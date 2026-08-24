import { updateCredentials } from "../../lib/authServerless";

export default function handler(req: any, res: any) {
  if (req.method !== "POST") {
    return res.status(405).json({ success: false, message: "Method not allowed" });
  }
  try {
    const { currentSecret, newUsername, newSecret } = req.body || {};
    const result = updateCredentials(currentSecret, newUsername, newSecret);
    if (result.success) {
      return res.json({ success: true, message: result.message });
    }
    return res.status(400).json({ success: false, message: result.message });
  } catch (e: any) {
    return res.status(500).json({ success: false, error: e.message });
  }
}
