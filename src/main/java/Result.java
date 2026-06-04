public class Result {

    private int requestId;
    private String url;
    private int statusCode;
    private int responseLength;
    private String redirectURL;

    public Result(int requestId, String url, int statusCode, int responseLength, String redirectURL) {
        this.requestId = requestId;
        this.url = url;
        this.statusCode = statusCode;
        this.responseLength = responseLength;
        this.redirectURL = redirectURL;
    }

    public int getRequestId() {
        return requestId;
    }

    public void setRequestId(int requestId) {
        this.requestId = requestId;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public void setStatusCode(int statusCode) {
        this.statusCode = statusCode;
    }

    public int getResponseLength() {
        return responseLength;
    }

    public void setResponseLength(int responseLength) {
        this.responseLength = responseLength;
    }

    public String getRedirectURL() {
        return redirectURL;
    }

    public void setRedirectURL(String redirectURL) {
        this.redirectURL = redirectURL;
    }
}
