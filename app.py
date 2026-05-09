import os, sys, io, uuid
from contextlib import redirect_stdout

from flask import Flask, render_template, request, send_file, flash, redirect, url_for
from werkzeug.utils import secure_filename
from PIL import Image
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from stego_core import AdversarialSteganography, SimpleSteganalyzer, compute_psnr, compute_ssim
from semantic_stego import SemanticStego
from evaluate import generate_test_image, benchmark_adversarial, benchmark_semantic

# --- App setup ---
app = Flask(__name__)
app.secret_key = "stego-master-suite-2026"

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
OUTPUT_FOLDER = os.path.join(BASE_DIR, "outputs")
EVAL_SAVE_DIR = os.path.join(BASE_DIR, "eval_outputs")

for folder in [UPLOAD_FOLDER, OUTPUT_FOLDER, EVAL_SAVE_DIR]:
    os.makedirs(folder, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["OUTPUT_FOLDER"] = OUTPUT_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

# Override SAVE_DIR in evaluate module
import evaluate
evaluate.SAVE_DIR = EVAL_SAVE_DIR

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in {"png", "jpg", "jpeg", "bmp"}

def get_unique_filename(filename):
    base, ext = os.path.splitext(secure_filename(filename))
    return f"{base}_{uuid.uuid4().hex[:8]}{ext}"

def capture_sem_decode(img_path, block_size=8, step=8):
    f = io.StringIO()
    with redirect_stdout(f):
        try:
            stego = SemanticStego(block_size=block_size, step=step)
            stego.decode(img_path)
        except Exception as e:
            print(f"[-] Error: {e}")
    output = f.getvalue()
    marker = "-" * 20
    parts = output.split(marker)
    if len(parts) >= 3:
        return parts[1].strip()
    return None

# --- Routes ---
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/encode", methods=["POST"])
def encode():
    try:
        file = request.files["cover_image"]
        if not file or not allowed_file(file.filename):
            flash("Invalid image file.", "danger")
            return redirect(url_for("index"))

        message = request.form["message"].strip()
        if not message:
            flash("Please enter a secret message.", "danger")
            return redirect(url_for("index"))

        method = request.form["method"]
        epsilon = int(request.form.get("epsilon", 2))
        block_size = int(request.form.get("block_size", 8))
        step = int(request.form.get("step", 8))

        cover_filename = get_unique_filename(file.filename)
        cover_path = os.path.join(UPLOAD_FOLDER, cover_filename)
        file.save(cover_path)

        stego_filename = f"stego_{method}_{uuid.uuid4().hex[:8]}.png"
        stego_path = os.path.join(OUTPUT_FOLDER, stego_filename)

        if method == "sem":
            stego_engine = SemanticStego(block_size=block_size, step=step)
            stego_engine.save_dir = OUTPUT_FOLDER
            stego_engine.encode(cover_path, message, stego_filename)

            stego_img = np.array(Image.open(stego_path).convert("RGB"))
            cover_img = np.array(Image.open(cover_path).convert("RGB"))
            analyzer = SimpleSteganalyzer()
            analysis = analyzer.analyze(stego_img)
            psnr_val = compute_psnr(cover_img, stego_img)
            ssim_val = compute_ssim(cover_img, stego_img)
            result = {
                "method": "Semantic (QIM)",
                "stego_file": stego_filename,
                "suspicion": analysis["overall_suspicion"],
                "psnr": psnr_val,
                "ssim": ssim_val,
                "verdict": analysis["verdict"],
            }
        else:
            pipeline = AdversarialSteganography(epsilon=epsilon)
            result_dict = pipeline.encode(cover_path, message, stego_path)
            analysis = result_dict["analysis"]
            ev = result_dict["evasion"]
            result = {
                "method": "Adversarial LSB",
                "stego_file": stego_filename,
                "original_score": analysis["original"]["overall_suspicion"],
                "lsb_score": analysis["after_lsb"]["overall_suspicion"],
                "adv_score": analysis["after_adversarial"]["overall_suspicion"],
                "evaded": ev["lsb_detected"] and not ev["adversarial_detected"],
            }

        return render_template("result_encode.html", result=result)

    except Exception as e:
        flash(f"Encoding failed: {str(e)}", "danger")
        return redirect(url_for("index"))

@app.route("/decode", methods=["POST"])
def decode():
    try:
        file = request.files["stego_image"]
        if not file or not allowed_file(file.filename):
            flash("Invalid image file.", "danger")
            return redirect(url_for("index"))

        method = request.form["method"]
        block_size = int(request.form.get("block_size", 8))
        step = int(request.form.get("step", 8))

        stego_filename = get_unique_filename(file.filename)
        stego_path = os.path.join(UPLOAD_FOLDER, stego_filename)
        file.save(stego_path)

        if method == "sem":
            message = capture_sem_decode(stego_path, block_size, step)
            if message is None:
                message = "No hidden message found or wrong parameters."
        else:
            pipeline = AdversarialSteganography()
            message = pipeline.decode(stego_path)
            if not message:
                message = "No hidden message found."

        return render_template("result_decode.html", message=message)

    except Exception as e:
        flash(f"Decoding failed: {str(e)}", "danger")
        return redirect(url_for("index"))

@app.route("/analyze", methods=["POST"])
def analyze():
    try:
        file = request.files["image"]
        if not file or not allowed_file(file.filename):
            flash("Invalid image.", "danger")
            return redirect(url_for("index"))
        
        img_filename = get_unique_filename(file.filename)
        img_path = os.path.join(UPLOAD_FOLDER, img_filename)
        file.save(img_path)

        img = np.array(Image.open(img_path).convert("RGB"))
        analyzer = SimpleSteganalyzer()
        analysis = analyzer.analyze(img)
        return render_template(
            "result_analyze.html",
            score=analysis["overall_suspicion"],
            verdict=analysis["verdict"],
            confidence=analysis["confidence"],
        )
    except Exception as e:
        flash(f"Analysis failed: {str(e)}", "danger")
        return redirect(url_for("index"))

@app.route("/evaluate", methods=["POST"])
def evaluate():
    try:
        if "cover_image" in request.files and request.files["cover_image"].filename:
            file = request.files["cover_image"]
            if allowed_file(file.filename):
                img_filename = get_unique_filename(file.filename)
                cover_path = os.path.join(UPLOAD_FOLDER, img_filename)
                file.save(cover_path)
                image = np.array(Image.open(cover_path).convert("RGB"))
            else:
                flash("Invalid format - using synthetic cover.", "warning")
                image = generate_test_image((256, 256))
        else:
            image = generate_test_image((256, 256))

        eval_cover_path = os.path.join(EVAL_SAVE_DIR, "eval_cover.png")
        Image.fromarray(image).save(eval_cover_path)

        adv_results = benchmark_adversarial(image)
        sem_results = benchmark_semantic(image)
        return render_template("result_evaluate.html",
                               adv_results=adv_results,
                               sem_results=sem_results)
    except Exception as e:
        flash(f"Evaluation error: {str(e)}", "danger")
        return redirect(url_for("index"))

@app.route("/download/<filename>")
def download_file(filename):
    file_path = os.path.join(OUTPUT_FOLDER, filename)
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    flash("File not found.", "danger")
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(debug=True)