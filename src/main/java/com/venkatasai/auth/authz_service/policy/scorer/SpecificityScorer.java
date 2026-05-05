package com.venkatasai.auth.authz_service.policy.scorer;

public class SpecificityScorer implements Scorer{

    @Override
    public int calculateScore(String resource, String path) {
        String[] resourceSplit = resource.split("/");
        String[] pathSplit = path.split("/");
        int score = 0;

        int len = Math.min(resourceSplit.length, pathSplit.length);

        for(int index=0; index<len; index++){
            if("*".equals(resourceSplit[index])){
                score++;
            } else if(resourceSplit[index].equals(pathSplit[index])){
                score+=2;
            }
        }

        return score;
    }
}
