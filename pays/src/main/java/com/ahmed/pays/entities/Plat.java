package com.ahmed.pays.entities;

import java.util.Date;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonFormat;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Entity
public class Plat {
    // Getters and Setters
    @Setter
    @Getter
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Id
    private Long idPlat; 

    @Setter
    @Getter
    private String nomPlat;
    @Getter
    @Setter
    private Double prixPlat;
    
    @Getter
    @Setter
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd") // Format for JSON serialization
    @Temporal(TemporalType.DATE)
    private Date dateCreation;
    @Getter
    @Setter
    @ManyToOne
    @JoinColumn(name = "id_pays") 
    private Pays pays;
    @OneToOne
    private Image image;
    @OneToMany (mappedBy = "plat")
    private List<Image> images;

    public List<Image> getImages() {
        return images;
    }

    public Plat() {
        super();
    }

    public String getNomPlat() {
        return nomPlat;
    }

    public Double getPrixPlat() {
        return prixPlat;
    }

    public Date getDateCreation() {
        return dateCreation;
    }

    public Pays getPays() {
        return pays;
    }

    public void setImages(List<Image> images) {
        this.images = images;
    }

    public Plat(String nomPlat, Double prixPlat, Pays pays, Date dateCreation) {
        super();
        this.nomPlat = nomPlat;
        this.prixPlat = prixPlat;
        this.pays = pays;
        this.dateCreation = dateCreation;
    }

    public void setImage(Image image) {
        this.image = image;
    }

    public Image getImage() {
        return image;
    }

    @Override
    public String toString() {
        return "Plat [idPlat=" + idPlat + ", nomPlat=" + nomPlat + ", prixPlat=" + prixPlat + ", pays=" + pays + ", dateCreation=" + dateCreation + "]";
    }
}
