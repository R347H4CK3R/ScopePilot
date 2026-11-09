package app.scopepilot.mobile;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.webkit.*;
import java.io.ByteArrayInputStream;

public final class MainActivity extends Activity {
    private WebView web;
    private android.webkit.ValueCallback<Uri[]> fileCallback;
    private static final String ORIGIN = "https://app.scopepilot.local/";
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        web = new WebView(this);
        web.setBackgroundColor(0xff091416);
        setContentView(web);
        WebSettings settings = web.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setAllowFileAccess(false);
        settings.setAllowContentAccess(false);
        settings.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        web.addJavascriptInterface(new Bridge(), "NativeBridge");
        web.setWebViewClient(new WebViewClient() {
            @Override public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) { return true; }
            @Override public WebResourceResponse shouldInterceptRequest(WebView view, WebResourceRequest request) {
                String url=request.getUrl().toString();
                if ("GET".equals(request.getMethod()) && (url.equals("https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/hackerone_data.json") || url.equals("https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/bugcrowd_data.json"))) return null;
                if (url.startsWith(ORIGIN)) {
                    String path=url.substring(ORIGIN.length());
                    if (path.equals("index.html") || path.equals("style.css") || path.equals("bundle.js")) {
                        try { return new WebResourceResponse(path.endsWith("html")?"text/html":path.endsWith("css")?"text/css":"text/javascript", "UTF-8", getAssets().open("web/"+path)); }
                        catch (Exception ignored) { }
                    }
                }
                return new WebResourceResponse("text/plain", "UTF-8", 403, "Blocked", java.util.Collections.emptyMap(), new ByteArrayInputStream(new byte[0]));
            }
        });
        web.setWebChromeClient(new WebChromeClient() {
            @Override public boolean onJsConfirm(WebView view,String url,String message,JsResult result) {
                new AlertDialog.Builder(MainActivity.this).setMessage(message).setPositiveButton("Confirm",(d,w)->result.confirm()).setNegativeButton("Cancel",(d,w)->result.cancel()).setOnCancelListener(d->result.cancel()).show(); return true;
            }
            @Override public boolean onShowFileChooser(WebView view,ValueCallback<Uri[]> callback,FileChooserParams params) {
                if(fileCallback!=null)fileCallback.onReceiveValue(null);
                fileCallback=callback;
                Intent intent=new Intent(Intent.ACTION_OPEN_DOCUMENT).setType("application/json").addCategory(Intent.CATEGORY_OPENABLE);
                try{startActivityForResult(intent,41);}catch(Exception e){fileCallback.onReceiveValue(null);fileCallback=null;}
                return true;
            }
        });
        web.loadUrl(ORIGIN+"index.html");
    }
    @Override protected void onActivityResult(int request,int result,Intent data) {
        super.onActivityResult(request,result,data);
        if(request==41&&fileCallback!=null){fileCallback.onReceiveValue(result==RESULT_OK&&data!=null&&data.getData()!=null?new Uri[]{data.getData()}:null);fileCallback=null;}
    }
    public final class Bridge {
        @JavascriptInterface public void openExternal(String raw) {
            runOnUiThread(()->{Uri uri=Uri.parse(raw);if(!"https".equals(uri.getScheme())||uri.getHost()==null||uri.getUserInfo()!=null)return;
                try{startActivity(new Intent(Intent.ACTION_VIEW,uri));}catch(Exception e){new AlertDialog.Builder(MainActivity.this).setMessage("No browser is available.").setPositiveButton("OK",null).show();}});
        }
        @JavascriptInterface public void exportReport(String text) {
            if(text==null||text.length()>200000)return;
            runOnUiThread(()->{Intent share=new Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_SUBJECT,"ScopePilot research draft").putExtra(Intent.EXTRA_TEXT,text);startActivity(Intent.createChooser(share,"Review before sharing"));});
        }
    }
    @Override protected void onDestroy(){if(fileCallback!=null)fileCallback.onReceiveValue(null);web.removeJavascriptInterface("NativeBridge");web.destroy();super.onDestroy();}
}
