package mx.unam.feu.models;

import jakarta.persistence.*;

@Entity
@Table(name="roles")
public class Role {
	@Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;
    
    @Enumerated(EnumType.STRING)
    @Column(length = 30)
    private TypeRole name;
    
    public Role() {

    }
    
    public Role(TypeRole name) {
        this.name = name;
    }

    public Integer getId() {
        return id;
    }
    
    public void setId(Integer id) {
        this.id = id;
    }
    
    public TypeRole getName() {
        return name;
    }
    
    public void setName(TypeRole name) {
        this.name = name;
    }
	
}
