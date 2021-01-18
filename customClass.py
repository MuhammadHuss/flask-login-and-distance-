import haversine as hs

class customClass:
    def calculateDistance(self,lat1,long1,lat2,long2):
        loc1=(lat1,long1)
        loc2=(lat2,long2)
        distance_km = hs.haversine(loc1,loc2)
        return str(distance_km)