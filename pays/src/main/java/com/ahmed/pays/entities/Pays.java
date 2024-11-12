package com.ahmed.pays.entities;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;

@Entity
public class Pays {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long idPays; 

    private String nomPays; 
    private String descriptionPays; 

    @JsonIgnore
    @OneToMany(mappedBy = "pays", cascade = CascadeType.ALL)
    private List<Plat> plats;

    public Long getIdPays() {
        return idPays;
    }

    public void setIdPays(Long idPays) {
        this.idPays = idPays;
    }

    public String getNomPays() {
        return nomPays;
    }

    public void setNomPays(String nomPays) {
        this.nomPays = nomPays;
    }

    public String getDescriptionPays() {
        return descriptionPays;
    }

    public void setDescriptionPays(String descriptionPays) {
        this.descriptionPays = descriptionPays;
    }

    public List<Plat> getPlats() {
        return plats;
    }

    public void setPlats(List<Plat> plats) {
        this.plats = plats;
    }
}
