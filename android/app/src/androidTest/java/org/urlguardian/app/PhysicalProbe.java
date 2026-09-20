package org.urlguardian.app;

import android.app.Activity;
import android.app.Instrumentation;
import android.content.Intent;
import android.os.Bundle;
import android.os.Debug;
import org.json.JSONArray;
import org.json.JSONObject;
import java.lang.reflect.*;
import java.util.*;

/** Test APK only. Reflects the exact R8 worker using its reviewed mapping.
 * No target URL is opened, no system settings or app data are cleared.
 * Stage clocks are the production worker's own System.nanoTime measurements.
 */
public class PhysicalProbe extends Instrumentation {
    private static final String PKG="org.urlguardian.app";
    private JSONObject config, classes;
    private final Map<String,String> reverse = new HashMap<>();
    private volatile Activity activity;
    private Object analyzer;
    private Constructor<?> workerConstructor;
    private Method workerMethod;
    private final java.util.concurrent.CountDownLatch resumed = new java.util.concurrent.CountDownLatch(1);
    private volatile int resumeCount=0;
    private String mode="benchmark";

    @Override public void callActivityOnResume(Activity a) {
        super.callActivityOnResume(a);
        if(a.getClass().getName().equals("org.urlguardian.app.MainActivity")) { activity=a; resumeCount++; resumed.countDown(); }
    }

    private void checkpoint(String value) { Bundle b=new Bundle(); b.putString("phase7Checkpoint",value); sendStatus(0,b); }

    @Override public void onCreate(Bundle arguments) { super.onCreate(arguments); if(arguments!=null) mode=arguments.getString("mode","benchmark"); start(); }

    private String screenText() {
        StringBuilder s=new StringBuilder();
        android.view.accessibility.AccessibilityNodeInfo root=getUiAutomation().getRootInActiveWindow();
        if(root!=null) collectText(root,s);
        return s.toString();
    }
    private void collectText(android.view.accessibility.AccessibilityNodeInfo n,StringBuilder s) {
        if("org.urlguardian.app".contentEquals(n.getPackageName()==null?"":n.getPackageName()) && n.getText()!=null) s.append(n.getText()).append('\n');
        for(int i=0;i<n.getChildCount();i++) { android.view.accessibility.AccessibilityNodeInfo c=n.getChild(i); if(c!=null) collectText(c,s); }
    }
    private String awaitResult() throws Exception {
        String s=""; for(int i=0;i<40;i++) { s=screenText(); if(s.contains("LOW_RISK")) return s; Thread.sleep(250); } return s;
    }
    private android.view.accessibility.AccessibilityNodeInfo findNode(android.view.accessibility.AccessibilityNodeInfo n,String value,boolean edit) {
        if(n==null) return null;
        if("org.urlguardian.app".contentEquals(n.getPackageName()==null?"":n.getPackageName())) {
            if(edit && "android.widget.EditText".contentEquals(n.getClassName())) return n;
            if(!edit && value.contentEquals(n.getText()==null?"":n.getText())) return n;
        }
        for(int i=0;i<n.getChildCount();i++) { android.view.accessibility.AccessibilityNodeInfo found=findNode(n.getChild(i),value,edit); if(found!=null)return found; }
        return null;
    }
    private android.view.accessibility.AccessibilityNodeInfo findContaining(android.view.accessibility.AccessibilityNodeInfo n,String value) {
        if(n==null)return null;
        String text=n.getText()==null?"":n.getText().toString().toLowerCase(java.util.Locale.ROOT);
        if(text.contains(value.toLowerCase(java.util.Locale.ROOT)))return n;
        for(int i=0;i<n.getChildCount();i++) { android.view.accessibility.AccessibilityNodeInfo found=findContaining(n.getChild(i),value);if(found!=null)return found; }
        return null;
    }
    private boolean clickNode(android.view.accessibility.AccessibilityNodeInfo node) {
        while(node!=null && !node.isClickable())node=node.getParent();
        return node!=null && node.performAction(android.view.accessibility.AccessibilityNodeInfo.ACTION_CLICK);
    }
    private android.view.accessibility.AccessibilityNodeInfo findScrollable(android.view.accessibility.AccessibilityNodeInfo n) {
        if(n==null)return null;if(n.isScrollable())return n;
        for(int i=0;i<n.getChildCount();i++){android.view.accessibility.AccessibilityNodeInfo found=findScrollable(n.getChild(i));if(found!=null)return found;}return null;
    }
    private void swipeUp() throws Exception {
        long down=android.os.SystemClock.uptimeMillis();
        getUiAutomation().injectInputEvent(android.view.MotionEvent.obtain(down,down,android.view.MotionEvent.ACTION_DOWN,500,1900,0),true);
        for(int i=1;i<=8;i++) {
            long now=android.os.SystemClock.uptimeMillis();float y=1900-(1400*i/8f);
            getUiAutomation().injectInputEvent(android.view.MotionEvent.obtain(down,now,android.view.MotionEvent.ACTION_MOVE,500,y,0),true);
            Thread.sleep(25);
        }
        long up=android.os.SystemClock.uptimeMillis();
        getUiAutomation().injectInputEvent(android.view.MotionEvent.obtain(down,up,android.view.MotionEvent.ACTION_UP,500,500,0),true);
    }
    private android.view.accessibility.AccessibilityNodeInfo findTextWithScroll(String value) throws Exception {
        for(int i=0;i<6;i++) {
            android.view.accessibility.AccessibilityNodeInfo root=getUiAutomation().getRootInActiveWindow();
            android.view.accessibility.AccessibilityNodeInfo found=findNode(root,value,false);if(found!=null)return found;
            android.view.accessibility.AccessibilityNodeInfo scroll=findScrollable(root);
            if(scroll==null||!scroll.performAction(android.view.accessibility.AccessibilityNodeInfo.ACTION_SCROLL_FORWARD)) {
                swipeUp();
            }
            Thread.sleep(250);
        }
        return null;
    }
    private String manual(String url) throws Exception {
        String visible="";
        boolean accepted=false;
        // A pending TI bundle import recreates MainActivity during startup, which
        // replaces the EditText node. Retype on a fresh node until the exact URL
        // is visible instead of failing the whole probe on that startup race.
        for(int attempt=0;attempt<6 && !accepted;attempt++) {
            android.view.accessibility.AccessibilityNodeInfo edit=null;
            for(int i=0;i<40 && edit==null;i++) { edit=findNode(getUiAutomation().getRootInActiveWindow(),"",true); if(edit==null)Thread.sleep(250); }
            if(edit==null)throw new IllegalStateException("Edit field not found");
            Bundle args=new Bundle(); args.putCharSequence(android.view.accessibility.AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE,url);
            if(!edit.performAction(android.view.accessibility.AccessibilityNodeInfo.ACTION_SET_TEXT,args))throw new IllegalStateException("SET_TEXT failed");
            for(int i=0;i<30;i++) { visible=screenText(); if(visible.contains(url))break; Thread.sleep(100); }
            accepted=visible.contains(url);
            if(!accepted)Thread.sleep(500);
        }
        if(!accepted)throw new IllegalStateException("Input field did not accept exact URL");
        android.view.accessibility.AccessibilityNodeInfo button=findNode(getUiAutomation().getRootInActiveWindow(),"分析網址",false);
        if(button==null)throw new IllegalStateException("Analyze button missing");
        if(!clickNode(button))throw new IllegalStateException("Analyze click failed");
        Thread.sleep(500);
        String expected="正規化網址："+url;
        String s=""; for(int i=0;i<40;i++) {
            s=screenText();
            if((s.contains(expected) && s.contains("原因代碼：")) || (s.contains(url) && s.contains("UNSUPPORTED_SCHEME")))return s;
            Thread.sleep(250);
        }
        throw new IllegalStateException("No result from manual entry");
    }
    private JSONObject uiChecks() throws Exception {
        JSONObject out=new JSONObject();
        String allow=manual("https://example.com/"); out.put("manualAllow",allow).put("manualAllowPassed",allow.contains("LOW_RISK"));
        String review=manual("https://www.paypal.com/login");out.put("review",review).put("reviewPassed",review.contains("ELEVATED_PROBABILITY") && review.contains("了解風險並繼續"));
        String blocked=manual("https://paypal-login.com/");
        out.put("block",blocked).put("blockPassed",blocked.contains("HIGH_PROBABILITY_WITH_EVIDENCE") && blocked.contains("BLOCK") && !blocked.contains("使用外部瀏覽器開啟") && !blocked.contains("了解風險並繼續"));
        JSONArray schemes=new JSONArray();
        for(String s:new String[]{"javascript:alert(1)","data:text/plain,x","file:///example","intent://example/","content://example/","ftp://example.com/","ws://example.com/"}) {
            String screen=manual(s);schemes.put(new JSONObject().put("scheme",s.split(":")[0]).put("passed",screen.contains("UNSUPPORTED_SCHEME") && !screen.contains("使用外部瀏覽器開啟") && !screen.contains("了解風險並繼續")));
        }
        out.put("unsupportedSchemes",schemes);
        String before=manual("https://example.com/");int old=resumeCount;
        runOnMainSync(()->activity.recreate()); for(int i=0;i<40 && resumeCount<=old;i++)Thread.sleep(250);
        Thread.sleep(600);String after=screenText();
        out.put("manualBeforeRecreation",before).put("manualAfterRecreation",after)
            .put("manualResultRestored",after.contains("LOW_RISK"));
        // This check intentionally exposes state loss; no false pass for an empty screen.
        String handoffSource=manual("https://example.com/");
        android.view.accessibility.AccessibilityNodeInfo external=findNode(getUiAutomation().getRootInActiveWindow(),"使用外部瀏覽器開啟",false);
        JSONObject handoff=new JSONObject().put("safeUrl","https://example.com/").put("buttonFound",external!=null);
        java.util.List<android.content.pm.ResolveInfo> resolved=getTargetContext().getPackageManager().queryIntentActivities(
            new Intent(Intent.ACTION_VIEW,android.net.Uri.parse("https://example.com/")).addCategory(Intent.CATEGORY_BROWSABLE),0);
        JSONArray packages=new JSONArray();for(android.content.pm.ResolveInfo info:resolved)if(!PKG.equals(info.activityInfo.packageName))packages.put(info.activityInfo.packageName);
        handoff.put("externalPackages",packages);
        if(external!=null && clickNode(external)) {
            Thread.sleep(1000);
            android.view.accessibility.AccessibilityNodeInfo root=getUiAutomation().getRootInActiveWindow();
            String focused=root==null||root.getPackageName()==null?"":root.getPackageName().toString();
            if(focused.equals("android")||focused.equals("com.android.intentresolver")) {
                android.view.accessibility.AccessibilityNodeInfo via=findContaining(root,"via");
                if(via!=null && clickNode(via)) { Thread.sleep(1000);root=getUiAutomation().getRootInActiveWindow();focused=root==null||root.getPackageName()==null?"":root.getPackageName().toString(); }
            }
            handoff.put("focusPackage",focused).put("leftOwnApp",!focused.isEmpty()&&!focused.equals(PKG));
        } else handoff.put("leftOwnApp",false);
        out.put("browserHandoff",handoff);
        return out.put("passed",out.getBoolean("manualAllowPassed") && out.getBoolean("reviewPassed") && out.getBoolean("blockPassed") && out.getBoolean("manualResultRestored") && handoff.getBoolean("leftOwnApp"));
    }
    private JSONObject lifecycle() throws Exception {
        JSONObject out=new JSONObject();
        String before=awaitResult(); out.put("before",before);
        int previous=resumeCount;
        runOnMainSync(()->activity.setRequestedOrientation(android.content.pm.ActivityInfo.SCREEN_ORIENTATION_LANDSCAPE));
        for(int i=0;i<40 && resumeCount<=previous;i++) Thread.sleep(250);
        out.put("landscapeResumed",resumeCount>previous).put("landscapeText",awaitResult());
        previous=resumeCount;
        runOnMainSync(()->activity.setRequestedOrientation(android.content.pm.ActivityInfo.SCREEN_ORIENTATION_UNSPECIFIED));
        for(int i=0;i<40 && resumeCount<=previous;i++) Thread.sleep(250);
        out.put("orientationRestored",resumeCount>previous);
        previous=resumeCount; runOnMainSync(()->activity.recreate());
        for(int i=0;i<40 && resumeCount<=previous;i++) Thread.sleep(250);
        String after=awaitResult(); out.put("explicitRecreationResumed",resumeCount>previous).put("after",after);
        previous=resumeCount; runOnMainSync(()->activity.moveTaskToBack(true)); Thread.sleep(500);
        Intent foreground=new Intent(Intent.ACTION_MAIN).setClassName(getTargetContext(),"org.urlguardian.app.MainActivity")
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK|Intent.FLAG_ACTIVITY_REORDER_TO_FRONT);
        getTargetContext().startActivity(foreground);
        for(int i=0;i<40 && resumeCount<=previous;i++)Thread.sleep(250);
        String foregroundText=awaitResult();out.put("backgroundForegroundResumed",resumeCount>previous).put("backgroundForegroundText",foregroundText);
        out.put("passed",before.contains("LOW_RISK") && out.getBoolean("landscapeResumed") && out.getString("landscapeText").contains("ALLOW") && after.contains("LOW_RISK") && foregroundText.contains("LOW_RISK"));
        return out.put("scope","safe ACTION_VIEW result; per-Activity orientation only, no settings writes");
    }
    private void writeFixture(String assetName,String fileName) throws Exception {
        try(java.io.InputStream input=getContext().getAssets().open("phase7/"+assetName)) {
            java.nio.file.Files.write(new java.io.File(getTargetContext().getFilesDir(),fileName).toPath(),input.readAllBytes());
        }
    }
    private String sha256(byte[] bytes) throws Exception {
        byte[] digest=java.security.MessageDigest.getInstance("SHA-256").digest(bytes);
        StringBuilder out=new StringBuilder();for(byte b:digest)out.append(String.format(java.util.Locale.ROOT,"%02x",b&255));return out.toString();
    }
    private String fixtureSha(String name) throws Exception {
        try(java.io.InputStream input=getContext().getAssets().open("phase7/"+name)){return sha256(input.readAllBytes());}
    }
    private String fileSha(String name) throws Exception {
        java.io.File file=new java.io.File(getTargetContext().getFilesDir(),name);return file.isFile()?sha256(java.nio.file.Files.readAllBytes(file.toPath())):"MISSING";
    }
    private void cleanBundles() {
        for(String name:new String[]{"ti_bundle.active.json","ti_bundle.pending.json","ti_bundle.backup.json","ti_bundle.previous.json","ti_bundle.import.json"})
            new java.io.File(getTargetContext().getFilesDir(),name).delete();
    }
    private void recreateAndWait() throws Exception {
        int previous=resumeCount;runOnMainSync(()->activity.recreate());
        for(int i=0;i<60 && resumeCount<=previous;i++)Thread.sleep(250);
        if(resumeCount<=previous)throw new IllegalStateException("Activity did not recreate for bundle import");
        Thread.sleep(400);
    }
    private JSONObject bundleLifecycle() throws Exception {
        JSONObject out=new JSONObject();
        String a=manual("https://phase7-a.example/");
        String shaA=fixtureSha("bundle_a.json"),shaB=fixtureSha("bundle_b.json");
        out.put("importA",a).put("activeAfterA",fileSha("ti_bundle.active.json"))
            .put("importAPassed",a.contains("KNOWN_MALICIOUS_GUARDRAIL")&&fileSha("ti_bundle.active.json").equals(shaA));
        writeFixture("bundle_b.json","ti_bundle.import.json");recreateAndWait();
        String b=manual("https://phase7-b.example/");
        out.put("importB",b).put("activeAfterB",fileSha("ti_bundle.active.json")).put("previousAfterB",fileSha("ti_bundle.previous.json"))
            .put("importBPassed",b.contains("KNOWN_MALICIOUS_GUARDRAIL")&&fileSha("ti_bundle.active.json").equals(shaB)&&fileSha("ti_bundle.previous.json").equals(shaA));
        checkpoint("bundle_b_guard="+b.contains("KNOWN_MALICIOUS_GUARDRAIL")+",previous_file="+new java.io.File(getTargetContext().getFilesDir(),"ti_bundle.previous.json").isFile());
        android.view.accessibility.AccessibilityNodeInfo rollback=findTextWithScroll("回復上一版情資");
        if(rollback==null||!clickNode(rollback))throw new IllegalStateException("Rollback action unavailable");
        Thread.sleep(700);
        String rolled=manual("https://phase7-a.example/");
        out.put("rollbackA",rolled).put("activeAfterRollback",fileSha("ti_bundle.active.json")).put("previousAfterRollback",fileSha("ti_bundle.previous.json"))
            .put("rollbackPassed",rolled.contains("KNOWN_MALICIOUS_GUARDRAIL")&&fileSha("ti_bundle.active.json").equals(shaA)&&fileSha("ti_bundle.previous.json").equals(shaB));
        writeFixture("bundle_corrupt.json","ti_bundle.import.json");recreateAndWait();
        String unchanged=manual("https://phase7-a.example/");
        out.put("corruptCandidate",unchanged).put("activeAfterCorrupt",fileSha("ti_bundle.active.json"))
            .put("corruptStagingRetained",new java.io.File(getTargetContext().getFilesDir(),"ti_bundle.import.json").isFile())
            .put("corruptRejectedActiveUnchanged",unchanged.contains("KNOWN_MALICIOUS_GUARDRAIL")&&fileSha("ti_bundle.active.json").equals(shaA)&&new java.io.File(getTargetContext().getFilesDir(),"ti_bundle.import.json").isFile());
        return out.put("passed",out.getBoolean("importAPassed")&&out.getBoolean("importBPassed")&&out.getBoolean("rollbackPassed")&&out.getBoolean("corruptRejectedActiveUnchanged"));
    }
    private JSONObject asset(String name) throws Exception {
        try (java.io.InputStream input = getContext().getAssets().open("phase7/" + name)) {
            return new JSONObject(new String(input.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8));
        }
    }
    private Object field(Object target, String original, String name) throws Exception {
        String renamed = classes.getJSONObject(original).getJSONObject("fields").getString(name);
        Field f = target.getClass().getDeclaredField(renamed); f.setAccessible(true); return f.get(target);
    }
    private Object jsonValue(Object value) throws Exception {
        if (value == null) return JSONObject.NULL;
        if (value instanceof Enum) return ((Enum<?>) value).name();
        if (value instanceof String || value instanceof Number || value instanceof Boolean) return value;
        if (value instanceof Iterable) { JSONArray a = new JSONArray(); for (Object v : (Iterable<?>)value) a.put(jsonValue(v)); return a; }
        String original = reverse.get(value.getClass().getName());
        if (original == null) return value.toString();
        JSONObject out = new JSONObject();
        JSONObject fields = classes.getJSONObject(original).getJSONObject("fields");
        for (Iterator<String> keys = fields.keys(); keys.hasNext();) {
            String key = keys.next();
            if (key.startsWith("$") || key.equals("Companion") || key.equals("INSTANCE")) continue;
            Field f = value.getClass().getDeclaredField(fields.getString(key));
            if (Modifier.isStatic(f.getModifiers())) continue;
            f.setAccessible(true); out.put(key, jsonValue(f.get(value)));
        }
        return out;
    }
    private JSONObject analyze(String url) throws Exception {
        Class<?> inputType = workerConstructor.getParameterTypes()[1];
        Object input;
        if(inputType == String.class) {
            input = url;
        } else if(inputType.isInterface()) {
            input = Proxy.newProxyInstance(inputType.getClassLoader(), new Class<?>[]{inputType},
                (p, m, args) -> {
                    if (m.getReturnType() == int.class) return System.identityHashCode(p);
                    if (m.getReturnType() == boolean.class) return p == args[0];
                    if (m.getReturnType() == void.class) return null;
                    return url;
                });
        } else {
            throw new IllegalStateException("Unsupported R8 input capture: "+inputType.getName());
        }
        Object worker = workerConstructor.newInstance(analyzer, input, null);
        try { return (JSONObject) jsonValue(workerMethod.invoke(worker, new Object[]{null})); }
        catch (InvocationTargetException e) { throw new Exception(e.getCause()); }
    }
    private JSONObject memory() throws Exception {
        Debug.MemoryInfo mi = new Debug.MemoryInfo(); Debug.getMemoryInfo(mi);
        JSONObject out = new JSONObject().put("totalPssKb", mi.getTotalPss())
            .put("nativePssKb", mi.nativePss).put("dalvikPssKb", mi.dalvikPss)
            .put("otherPssKb", mi.otherPss);
        JSONObject stats = new JSONObject();
        for (Map.Entry<String,String> e : mi.getMemoryStats().entrySet()) stats.put(e.getKey(),e.getValue());
        return out.put("summary",stats);
    }
    private JSONObject stats(List<Double> values) throws Exception {
        List<Double> s = new ArrayList<>(values); Collections.sort(s);
        double sum=0; for(double v:s) sum+=v;
        return new JSONObject().put("averageMs",sum/s.size()).put("minMs",s.get(0)).put("maxMs",s.get(s.size()-1))
            .put("p50Ms",s.get((int)((s.size()-1)*.50))).put("p95Ms",s.get((int)((s.size()-1)*.95)));
    }
    @Override public void onStart() {
        JSONObject report = new JSONObject();
        try {
            config=asset("mapping.json"); classes=config.getJSONObject("classes");
            checkpoint("assets_loaded");
            for(Iterator<String> it=classes.keys();it.hasNext();) { String k=it.next(); reverse.put(classes.getJSONObject(k).getString("class"),k); }
            // Fail rather than measuring a different installed artifact.
            java.security.MessageDigest md=java.security.MessageDigest.getInstance("SHA-256");
            try(java.io.InputStream input=new java.io.FileInputStream(getTargetContext().getApplicationInfo().sourceDir)) {
                byte[] b=new byte[65536]; int n; while((n=input.read(b))!=-1) md.update(b,0,n);
            }
            StringBuilder hash=new StringBuilder(); for(byte b:md.digest()) hash.append(String.format(java.util.Locale.ROOT,"%02x",b&255));
            if(!hash.toString().equals(config.getString("apkSha256"))) throw new IllegalStateException("Installed APK hash mismatch");
            report.put("apkSha256",hash.toString()).put("build","FULL_R8_TEST_SIGNED_RELEASE_CANDIDATE")
                .put("device",android.os.Build.MODEL).put("abi",android.os.Build.SUPPORTED_ABIS[0]).put("androidApi",android.os.Build.VERSION.SDK_INT);
            long start=System.nanoTime();
            if(mode.equals("bundle")) { cleanBundles();writeFixture("bundle_a.json","ti_bundle.import.json"); }
            Intent launch=new Intent(Intent.ACTION_MAIN).setClassName(getTargetContext(),"org.urlguardian.app.MainActivity").addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            if(mode.equals("lifecycle")) launch.setAction(Intent.ACTION_VIEW).setData(android.net.Uri.parse("https://example.com/"));
            getTargetContext().startActivity(launch);
            if(!resumed.await(30,java.util.concurrent.TimeUnit.SECONDS)) throw new IllegalStateException("MainActivity did not resume within 30 seconds");
            checkpoint("activity_ready");
            report.put("activityLaunchIncludingAssetSessionInitMs",(System.nanoTime()-start)/1e6);
            if(mode.equals("lifecycle")) {
                JSONObject check=lifecycle(); report.put("lifecycle",check).put("passed",check.getBoolean("passed")); return;
            }
            if(mode.equals("ui")) { JSONObject check=uiChecks();report.put("ui",check).put("passed",check.getBoolean("passed"));return; }
            if(mode.equals("bundle")) { JSONObject check=bundleLifecycle();report.put("bundle",check).put("passed",check.getBoolean("passed"));return; }
            analyzer=field(activity,"org.urlguardian.app.MainActivity","analyzer");
            if(analyzer==null) throw new IllegalStateException("Analyzer unavailable");
            Class<?> worker=Class.forName(config.getString("workerClass"),true,activity.getClassLoader());
            for(Constructor<?> c:worker.getDeclaredConstructors()) if(c.getParameterCount()==3 && c.getParameterTypes()[0].isInstance(analyzer)) workerConstructor=c;
            if(workerConstructor==null) throw new IllegalStateException("Worker constructor missing");
            workerConstructor.setAccessible(true);
            workerMethod=worker.getDeclaredMethod(config.getString("workerMethod"),Object.class); workerMethod.setAccessible(true);
            JSONObject first=analyze("https://example.com/"); report.put("coldFirstAnalysis",first.getJSONObject("timings"));
            checkpoint("first_analysis_complete");
            report.put("initialResult",first).put("memoryBefore",memory());
            final int warmup=20, runs=100;
            for(int i=0;i<warmup;i++) analyze("https://example.com/warmup");
            Map<String,List<Double>> samples=new LinkedHashMap<>(); JSONArray raw=new JSONArray();
            long peak=0;
            for(int i=0;i<runs;i++) {
                JSONObject t=analyze("https://sub"+i+".example.com/login?id=REDACTED").getJSONObject("timings"); raw.put(t);
                for(Iterator<String> it=t.keys();it.hasNext();) { String k=it.next(); samples.computeIfAbsent(k,x->new ArrayList<>()).add(t.getDouble(k)); }
                if(i%10==0) peak=Math.max(peak,Debug.getPss());
            }
            JSONObject bench=new JSONObject().put("warmupCount",warmup).put("measurementCount",runs).put("rawTimings",raw)
                .put("peakSampledPssKb",peak).put("pssSampling","every 10 analyses, outside stage timing")
                .put("clock","production System.nanoTime; excludes reflection, ADB, UI and memory sampling")
                .put("brandAndShortenerTiming","combined intelMs; separate stages NOT MEASURED in unmodified RC");
            for(Map.Entry<String,List<Double>> e:samples.entrySet()) bench.put(e.getKey(),stats(e.getValue()));
            report.put("benchmark",bench);
            checkpoint("benchmark_complete");
            JSONArray memorySamples=new JSONArray(); memorySamples.put(new JSONObject().put("analyses",0).put("memory",memory()));
            long stressStart=System.nanoTime();
            for(int i=0;i<500;i++) {
                JSONObject result=analyze("https://example.com/path"+(i%20)+"?q=REDACTED");
                if(!result.getJSONObject("decision").getString("engineVersion").equals("DecisionPolicyV1")) throw new AssertionError("engine drift");
                if((i+1)%100==0) memorySamples.put(new JSONObject().put("analyses",i+1).put("memory",memory()));
            }
            report.put("stability",new JSONObject().put("completedAnalyses",500).put("durationMs",(System.nanoTime()-stressStart)/1e6)
                .put("memorySamples",memorySamples).put("browserHandoffs",0).put("passed",true));
            checkpoint("stress_complete");
            JSONArray golden=asset("golden.json").getJSONArray("fixtures"), actualGolden=new JSONArray();
            for(int i=0;i<golden.length();i++) actualGolden.put(analyze(golden.getJSONObject(i).getString("input")));
            report.put("goldenActual",actualGolden);
            JSONObject corpus=asset("adversarial.json"), actual=new JSONObject();
            for(String key:new String[]{"urlCases","brandCases","shortenerCases"}) {
                JSONArray rows=corpus.getJSONArray(key), outputs=new JSONArray();
                for(int i=0;i<rows.length();i++) {
                    JSONObject row=rows.getJSONObject(i), out=new JSONObject().put("input",row.getString("input"));
                    try { out.put("result",analyze(row.getString("input"))); }
                    catch(Exception e) { out.put("rejected",true).put("error",e.toString()); }
                    outputs.put(out);
                }
                actual.put(key,outputs);
            }
            report.put("adversarialActual",actual).put("passed",true);
        } catch(Throwable e) {
            try { report.put("passed",false).put("error",android.util.Log.getStackTraceString(e)); } catch(Exception ignored) { }
        } finally {
            if(mode.equals("bundle"))cleanBundles();
            if(activity!=null) runOnMainSync(()->activity.finish());
            Bundle out=new Bundle(); out.putString("phase7",report.toString()); finish(Activity.RESULT_OK,out);
        }
    }
}
