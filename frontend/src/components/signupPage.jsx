import { useState } from "react";
import { Shield } from "lucide-react";

export default function Signup() {
  const [formData, setFormData] = useState({
    name: "",
    email: "",
    password: "",
    company: ""
  });
  const [loading, setLoading] = useState(false);

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    setLoading(true);
    setTimeout(() => {
      alert("Account created successfully (demo mode)");
      setLoading(false);
    }, 1400);
  };

  return (
    <div className="min-h-screen bg-black text-white flex items-center justify-center p-6">
      <div className="absolute inset-0 bg-[radial-gradient(#10b981_0.8px,transparent_1px)] bg-[length:40px_40px] opacity-10" />

      <div className="w-full max-w-md relative z-10">
        <div className="flex justify-center mb-8">
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 bg-gradient-to-br from-emerald-400 to-cyan-400 rounded-2xl flex items-center justify-center">
              <Shield className="w-7 h-7 text-black" />
            </div>
            <div>
              <div className="text-3xl font-bold tracking-tighter">ITEK</div>
              <div className="text-xs text-emerald-400 -mt-1 font-mono">VAPT PLATFORM</div>
            </div>
          </div>
        </div>

        <div className="bg-zinc-950 border border-white/10 rounded-3xl p-10 shadow-2xl">
          <h2 className="text-3xl font-bold text-center mb-2">Join the Red Team</h2>
          <p className="text-gray-400 text-center mb-8">Create your ITEK account</p>

          <form onSubmit={handleSubmit} className="space-y-6">
            <div>
              <label className="block text-sm text-gray-400 mb-2">Full Name</label>
              <input
                type="text"
                name="name"
                value={formData.name}
                onChange={handleChange}
                className="w-full bg-black border border-white/20 focus:border-emerald-500 rounded-2xl px-5 py-4 outline-none transition"
                placeholder="John Doe"
                required
              />
            </div>

            <div>
              <label className="block text-sm text-gray-400 mb-2">Company / Organization</label>
              <input
                type="text"
                name="company"
                value={formData.company}
                onChange={handleChange}
                className="w-full bg-black border border-white/20 focus:border-emerald-500 rounded-2xl px-5 py-4 outline-none transition"
                placeholder="Acme Corp"
              />
            </div>

            <div>
              <label className="block text-sm text-gray-400 mb-2">Work Email</label>
              <input
                type="email"
                name="email"
                value={formData.email}
                onChange={handleChange}
                className="w-full bg-black border border-white/20 focus:border-emerald-500 rounded-2xl px-5 py-4 outline-none transition"
                placeholder="you@company.com"
                required
              />
            </div>

            <div>
              <label className="block text-sm text-gray-400 mb-2">Password</label>
              <input
                type="password"
                name="password"
                value={formData.password}
                onChange={handleChange}
                className="w-full bg-black border border-white/20 focus:border-emerald-500 rounded-2xl px-5 py-4 outline-none transition"
                placeholder="Create a strong password"
                required
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-gradient-to-r from-emerald-400 to-cyan-400 text-black font-semibold py-4 rounded-2xl text-lg hover:brightness-110 transition disabled:opacity-70"
            >
              {loading ? "CREATING ACCOUNT..." : "CREATE ACCOUNT"}
            </button>
          </form>

          <div className="text-center mt-8 text-sm text-gray-500">
            Already have an account?{" "}
            <a href="/login" className="text-emerald-400 hover:underline">Sign in</a>
          </div>
        </div>

        <div className="text-center mt-8 text-xs text-gray-600">
          14-day free trial • No credit card required
        </div>
      </div>
    </div>
  );
}