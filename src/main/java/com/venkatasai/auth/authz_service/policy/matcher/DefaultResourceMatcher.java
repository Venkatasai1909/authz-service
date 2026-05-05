package com.venkatasai.auth.authz_service.policy.matcher;

public class DefaultResourceMatcher implements ResourceMatcher{

    @Override
    public boolean matches(String resource, String path) {
        if(resource == null || path == null){
            return false;
        }

        String[] resourceSplit = resource.split("/");
        String[] pathSplit = path.split("/");

        int len = Math.min(resourceSplit.length, pathSplit.length);

        for(int index=0; index<len; index++){
            if("*".equals(resourceSplit[index])){
                continue;
            }

            if(!resourceSplit[index].equals(pathSplit[index])){
                return false;
            }
        }

        return true;
    }
}
